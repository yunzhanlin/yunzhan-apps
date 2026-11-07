"""Bounded pre-write observation, never queue exemption or installer retry."""
import contextlib
import hashlib
import importlib.util
import io
import json
import os
import pathlib
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

spec = importlib.util.spec_from_file_location('statistics_reader_admission', pathlib.Path(__file__).with_name('upgrade-release.py'))
upgrade = importlib.util.module_from_spec(spec)
spec.loader.exec_module(upgrade)


def reader_error(**changes):
    value = {'format': 1, 'kind': 'native-program-unit-refusal-v1',
             'unit': 'panel-geodata-verify-cache.service', 'load_state': 'loaded',
             'active_state': 'active', 'sub_state': 'running',
             'inventory_sha256': 'a' * 64}
    value.update(changes)
    message = 'native program operation is active, failed or transitional; upgrade refused'
    if value.get('kind') == 'native-program-job-refusal-v1':
        message = 'native program operation is queued; upgrade refused'
    return upgrade.CommandFailure('/owned/panel-executor', 1, '',
                                  '2026/10/24 05:00:00 ' + message + '\n' + json.dumps(value) + '\n')


class StatisticsReaderClassificationTests(unittest.TestCase):
    def test_only_exact_complete_original_fixed_unit_and_known_active_states(self):
        for active, sub in [('activating', 'start-pre'), ('activating', 'start'),
                            ('activating', 'start-post'), ('active', 'running'),
                            ('deactivating', 'stop-post')]:
            with self.subTest(active=active, sub=sub):
                self.assertTrue(upgrade.original_statistics_reader_can_be_observed_again(
                    reader_error(active_state=active, sub_state=sub)))
        for state in ('waiting', 'running'):
            value = {'format': 1, 'kind': 'native-program-job-refusal-v1',
                     'unit': 'panel-geodata-verify-cache.service', 'job_id': '101',
                     'job_type': 'start', 'job_state': state, 'inventory_sha256': 'a' * 64}
            error = upgrade.CommandFailure('panel-executor', 1, '',
                'native program operation is queued; upgrade refused\n' + json.dumps(value))
            self.assertTrue(upgrade.original_statistics_reader_can_be_observed_again(error))

    def test_aliases_installer_units_failed_masked_unknown_idle_and_extra_fields_refuse(self):
        errors = [reader_error(unit=name) for name in (
            'panel-geodata-verify-other.service', 'panel-geodata-verify-cache@abc.service',
            'panel-statistics-geodata@123.service', 'panel-mysql-overwrite-recovery.service',
            'panel-compose-recovery.service', 'panel-disk-host-example.scope')]
        for changes in ({'format': True}, {'extra': 'unknown'}, {'load_state': 'masked'},
                        {'active_state': 'failed', 'sub_state': 'failed'},
                        {'active_state': 'active', 'sub_state': 'exited'},
                        {'active_state': 'inactive', 'sub_state': 'dead'},
                        {'active_state': 'activating', 'sub_state': 'future'},
                        {'active_state': 'deactivating', 'sub_state': 'stop-sigkill'},
                        {'inventory_sha256': 'invalid'}):
            errors.append(reader_error(**changes))
        for error in errors:
            with self.subTest(error=error.output['stderr']['sha256']):
                self.assertFalse(upgrade.original_statistics_reader_can_be_observed_again(error))

    def test_legacy_partial_duplicate_oversized_wrong_child_output_and_exit_refuse(self):
        text = reader_error().output['stderr']['text']
        values = [text + 'extra', text + '\n', text.replace('\n', '\r\n'),
                  text.replace('"format": 1', '"format": 1, "format": 1'),
                  'native program operation is active, failed or transitional; upgrade refused',
                  text * 100]
        errors = [upgrade.CommandFailure('panel-executor', 1, '', value) for value in values]
        errors.extend([upgrade.CommandFailure('panel-executor', 1, 'not empty', text),
                       upgrade.CommandFailure('other', 1, '', text),
                       upgrade.CommandFailure('panel-executor', 2, '', text),
                       upgrade.CommandFailure('panel-executor', True, '', text)])
        for error in errors:
            self.assertFalse(upgrade.original_statistics_reader_can_be_observed_again(error))

    def test_queued_stop_failed_unknown_or_noncanonical_identity_refuse(self):
        value = {'format': 1, 'kind': 'native-program-job-refusal-v1',
                 'unit': 'panel-geodata-verify-cache.service', 'job_id': '101',
                 'job_type': 'start', 'job_state': 'running', 'inventory_sha256': 'a' * 64}
        for changes in ({'job_type': 'stop'}, {'job_state': 'failed'}, {'job_id': '01'},
                        {'job_id': '18446744073709551616'}, {'extra': 1}):
            changed = {**value, **changes}
            error = upgrade.CommandFailure('panel-executor', 1, '',
                'native program operation is queued; upgrade refused\n' + json.dumps(changed))
            self.assertFalse(upgrade.original_statistics_reader_can_be_observed_again(error))


class StatisticsReaderAdmissionTests(unittest.TestCase):
    def transaction(self):
        return upgrade.Upgrade(pathlib.Path('/candidate'))

    def test_each_new_complete_guard_must_succeed_and_diagnostics_keep_original_hash(self):
        transaction = self.transaction()
        first, second = reader_error(), reader_error(active_state='deactivating', sub_state='stop-post')
        transaction.queue_check = mock.Mock(side_effect=[first, second, None])
        output = io.StringIO()
        with mock.patch.object(upgrade.time, 'sleep') as sleep, contextlib.redirect_stderr(output):
            transaction.preflight_queue_check()
        self.assertEqual(transaction.queue_check.call_count, 3)
        self.assertEqual(sleep.call_args_list, [mock.call(5), mock.call(5)])
        records = [json.loads(line) for line in output.getvalue().splitlines()]
        self.assertEqual([r['readonly_recheck'] for r in records], [1, 2])
        for record, error in zip(records, (first, second)):
            self.assertEqual(record['kind'], 'native-statistics-reader-admission')
            self.assertEqual(record['operation'], 'immutable-statistics-cache-validation')
            self.assertEqual(record['maximum_observation_seconds'], 310)
            self.assertEqual(record['maximum_readonly_rechecks'], 64)
            self.assertEqual(record['original_observation'], upgrade.public_queue_refusal_diagnostic(error))
            self.assertFalse(record['mutating_installer_replay'])
        self.assertNotIn('panel-geodata-verify-cache.service', output.getvalue())

    def test_no_privileged_side_effect_or_new_lease_while_waiting(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary).resolve()
            original = root / 'original'
            original.write_bytes(b'original source and data')
            before = (original.stat().st_ino, original.stat().st_mode,
                      hashlib.sha256(original.read_bytes()).hexdigest())
            transaction = upgrade.Upgrade(root, root)
            transaction.queue_check = mock.Mock(side_effect=[reader_error(), None])
            with mock.patch.object(upgrade.time, 'sleep'), \
                    mock.patch.object(upgrade.subprocess, 'run', side_effect=AssertionError('unexpected process')), \
                    contextlib.redirect_stderr(io.StringIO()):
                transaction.preflight_queue_check()
            self.assertEqual(list(root.iterdir()), [original])
            self.assertEqual((original.stat().st_ino, original.stat().st_mode,
                              hashlib.sha256(original.read_bytes()).hexdigest()), before)
            self.assertEqual(transaction.locks, [])
            self.assertIsNone(transaction.backup)
            self.assertFalse(transaction.pending_created)
            self.assertFalse(transaction.stopping)

    def test_current_guard_failure_unknown_or_changed_unit_stops_without_borrowing_identity(self):
        for later in (reader_error(active_state='failed', sub_state='failed'),
                      reader_error(unit='panel-compose-recovery.service'),
                      upgrade.CommandFailure('panel-executor', 1, '', 'context deadline exceeded'),
                      ValueError('changed source identity'),
                      subprocess.TimeoutExpired('fixed-reader', 5)):
            transaction = self.transaction()
            transaction.queue_check = mock.Mock(side_effect=[reader_error(), later, None])
            with mock.patch.object(upgrade.time, 'sleep') as sleep, \
                    contextlib.redirect_stderr(io.StringIO()), self.assertRaises(type(later)) as caught:
                transaction.preflight_queue_check()
            self.assertIs(caught.exception, later)
            self.assertEqual(transaction.queue_check.call_count, 2)
            sleep.assert_called_once_with(5)

    def test_mutation_pending_backup_or_runtime_lease_never_enters_wait(self):
        changes = ({'backup': pathlib.Path('/owned')}, {'pending_created': True},
                   {'stopping': True}, {'changed': True}, {'locks': [10, 11]},
                   {'locks': [-1]}, {'layout': 'unknown'})
        for changed in changes:
            transaction = self.transaction()
            for key, value in changed.items():
                setattr(transaction, key, value)
            error = reader_error()
            transaction.queue_check = mock.Mock(side_effect=error)
            with mock.patch.object(upgrade.time, 'sleep') as sleep, self.assertRaises(upgrade.CommandFailure) as caught:
                transaction.preflight_queue_check()
            self.assertIs(caught.exception, error)
            self.assertEqual(transaction.queue_check.call_count, 1)
            sleep.assert_not_called()

    def test_scope_is_revalidated_before_every_further_read(self):
        transaction = self.transaction()
        error = reader_error()
        transaction.queue_check = mock.Mock(side_effect=[error, None])
        transaction.preflight_admission_is_readonly = mock.Mock(side_effect=[True, False])
        with mock.patch.object(upgrade.time, 'sleep'), contextlib.redirect_stderr(io.StringIO()), \
                self.assertRaises(upgrade.CommandFailure) as caught:
            transaction.preflight_queue_check()
        self.assertIs(caught.exception, error)
        self.assertEqual(transaction.queue_check.call_count, 1)

    def test_real_monotonic_deadline_refuses_and_reserves_original_guard_deadline(self):
        transaction = self.transaction()
        errors = []
        clock = [1000.0]
        def failed():
            error = reader_error()
            errors.append(error)
            raise error
        transaction.queue_check = mock.Mock(side_effect=failed)
        with mock.patch.object(upgrade.time, 'monotonic', side_effect=lambda: clock[0]), \
                mock.patch.object(upgrade.time, 'sleep', side_effect=lambda delay: clock.__setitem__(0, clock[0] + delay)), \
                contextlib.redirect_stderr(io.StringIO()), self.assertRaises(upgrade.CommandFailure) as caught:
            transaction.preflight_queue_check()
        self.assertIs(caught.exception, errors[-1])
        self.assertLessEqual(clock[0] - 1000.0, 310)
        self.assertLessEqual(transaction.queue_check.call_count, 65)

    def test_count_cap_refuses_even_if_clock_does_not_advance(self):
        transaction = self.transaction()
        error = reader_error()
        transaction.queue_check = mock.Mock(side_effect=error)
        with mock.patch.object(upgrade.time, 'monotonic', return_value=1000), \
                mock.patch.object(upgrade.time, 'sleep') as sleep, contextlib.redirect_stderr(io.StringIO()), \
                self.assertRaises(upgrade.CommandFailure) as caught:
            transaction.preflight_queue_check()
        self.assertIs(caught.exception, error)
        self.assertEqual(transaction.queue_check.call_count, 65)
        self.assertEqual(sleep.call_count, 64)

    def test_late_success_is_not_a_bounded_admission_proof(self):
        transaction = self.transaction()
        clock = [1000.0]
        def success():
            clock[0] = 1311.0
        calls = [0]
        def next_read():
            calls[0] += 1
            if calls[0] == 1:
                raise reader_error()
            success()
        transaction.queue_check = mock.Mock(side_effect=next_read)
        with mock.patch.object(upgrade.time, 'monotonic', side_effect=lambda: clock[0]), \
                mock.patch.object(upgrade.time, 'sleep'), contextlib.redirect_stderr(io.StringIO()), \
                self.assertRaisesRegex(ValueError, 'observation budget expired'):
            transaction.preflight_queue_check()
        self.assertEqual(calls[0], 2)

    def test_periodic_recovery_keeps_its_existing_two_short_rechecks(self):
        value = {'format': 1, 'kind': 'native-program-job-refusal-v1',
                 'unit': 'panel-mysql-overwrite-recovery.service', 'job_id': '101',
                 'job_type': 'start', 'job_state': 'running', 'inventory_sha256': 'b' * 64}
        periodic = upgrade.CommandFailure('panel-executor', 1, '',
            'native program operation is queued; upgrade refused\n' + json.dumps(value))
        transaction = self.transaction()
        transaction.queue_check = mock.Mock(side_effect=[reader_error(), periodic, periodic, periodic])
        with mock.patch.object(upgrade.time, 'sleep') as sleep, contextlib.redirect_stderr(io.StringIO()), \
                self.assertRaises(upgrade.CommandFailure) as caught:
            transaction.preflight_queue_check()
        self.assertIs(caught.exception, periodic)
        self.assertEqual(sleep.call_args_list, [mock.call(5), mock.call(0.25), mock.call(0.25)])

    def test_direct_mutation_guard_is_not_the_readonly_admission_protocol(self):
        self.assertNotEqual(upgrade.Upgrade.queue_check, upgrade.Upgrade.preflight_queue_check)
        source = pathlib.Path(__file__).with_name('upgrade-release.py').read_text()
        self.assertIn('self.stop_timer()\n        self.queue_check()', source)
        self.assertNotIn('self.stop_timer()\n        self.preflight_queue_check()', source)


@unittest.skipUnless(sys.platform.startswith('linux') and os.geteuid() == 0,
                     'actual Root Linux filesystem/SQLite transaction fixture required')
class StatisticsReaderTransactionTests(unittest.TestCase):
    def fixtures(self):
        def load(name, filename):
            item = importlib.util.spec_from_file_location(name, pathlib.Path(__file__).with_name(filename))
            module = importlib.util.module_from_spec(item)
            item.loader.exec_module(module)
            return module
        production = load('reader_production_fixtures', 'test_production_upgrade.py')
        development = load('reader_development_fixtures', 'test_development_upgrade_safety.py')
        return ((production.UpgradeTransactionTests().fixture, production.upgrade),
                (development.DevelopmentUpgradeTransactionTests().fixture, development.development.production))

    def test_real_filesystem_both_layouts_observe_before_each_readonly_admission(self):
        for fixture, module in self.fixtures():
            for occurrence in (1, 2):
                with fixture() as (transaction, runner, root):
                    original = transaction.run_command
                    checks = []
                    def run(*args, **kwargs):
                        if args[1:] == ('--check-program-upgrade-queues',):
                            checks.append(len(transaction.locks))
                            if len(checks) == occurrence:
                                self.assertIsNone(transaction.backup)
                                self.assertFalse(transaction.pending_created)
                                self.assertFalse(transaction.changed)
                                raise module.CommandFailure('panel-executor', 1, '',
                                    reader_error().output['stderr']['text'])
                        return original(*args, **kwargs)
                    transaction.run_command = run
                    with mock.patch.object(module.time, 'sleep') as sleep, contextlib.redirect_stderr(io.StringIO()):
                        transaction.run()
                    self.assertTrue(transaction.committed)
                    self.assertIn(mock.call(5), sleep.call_args_list)
                    self.assertFalse(any(len(call) > 1 and call[1] in ('stop', 'start', 'reset-failed')
                                         and 'panel-geodata-verify-cache.service' in call for call in runner.calls))
                    with sqlite3.connect(root / 'var/lib/panel/panel.db') as db:
                        self.assertEqual(db.execute('SELECT value FROM configuration').fetchone(), ('original',))

    def test_real_new_sql_job_during_wait_refuses_before_backup_or_program_change(self):
        for fixture, module in self.fixtures():
            with fixture() as (transaction, runner, root):
                original = transaction.run_command
                def run(*args, **kwargs):
                    if args[1:] == ('--check-program-upgrade-queues',):
                        with sqlite3.connect(root / 'var/lib/panel/panel.db') as db:
                            db.execute("INSERT INTO runtime_jobs VALUES ('new-original', 'running')")
                        raise module.CommandFailure('panel-executor', 1, '',
                            reader_error().output['stderr']['text'])
                    return original(*args, **kwargs)
                transaction.run_command = run
                with mock.patch.object(module.time, 'sleep'), contextlib.redirect_stderr(io.StringIO()), \
                        self.assertRaisesRegex(ValueError, 'wait for active'):
                    transaction.run()
                self.assertIsNone(transaction.backup)
                self.assertFalse(transaction.pending_created)
                self.assertFalse(transaction.changed)
                self.assertEqual(list((root / 'var/backups/panel/system').iterdir()), [])
                self.assertFalse(any(len(call) > 1 and call[1] in ('stop', 'start', 'reset-failed', 'daemon-reload')
                                     for call in runner.calls))

    def test_real_under_runtime_lease_guard_stays_direct_and_never_waits(self):
        for fixture, module in self.fixtures():
            with fixture() as (transaction, runner, root):
                original = transaction.run_command
                checks = []
                error = module.CommandFailure('panel-executor', 1, '', reader_error().output['stderr']['text'])
                def run(*args, **kwargs):
                    if args[1:] == ('--check-program-upgrade-queues',):
                        checks.append(len(transaction.locks))
                        if len(checks) == 3:
                            self.assertIsNotNone(transaction.backup)
                            self.assertGreaterEqual(len(transaction.locks), 2)
                            raise error
                    return original(*args, **kwargs)
                transaction.run_command = run
                with mock.patch.object(module.time, 'sleep') as sleep, contextlib.redirect_stderr(io.StringIO()), \
                        self.assertRaises(module.CommandFailure) as caught:
                    transaction.run()
                self.assertIs(caught.exception, error)
                self.assertFalse(transaction.changed)
                self.assertEqual(len(checks), 3)
                self.assertNotIn(mock.call(5), sleep.call_args_list)


if __name__ == '__main__':
    unittest.main(verbosity=2)
