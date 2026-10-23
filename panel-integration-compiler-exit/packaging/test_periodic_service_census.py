"""Bounded read-only census fixtures; native systemd acceptance is separate."""
import contextlib
import hashlib
import importlib.util
import io
import json
import os
import pathlib
import sqlite3
import sys
import unittest
from unittest import mock

HERE = pathlib.Path(__file__).resolve().parent


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, HERE / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


upgrade = load('census_upgrade', 'upgrade-release.py')
RECOVERY = 'panel-mysql-overwrite-recovery.service'
IDLE = 'LoadState=loaded\nActiveState=inactive\nSubState=dead\nUnitFileState=static'
TRANSITION = IDLE.replace('inactive', 'activating').replace('dead', 'start')


class PeriodicServiceCensusPolicyTests(unittest.TestCase):
    def transaction(self, recovery):
        observations = iter(recovery)
        calls = []
        def run(*args, **kwargs):
            calls.append(args)
            self.assertEqual(kwargs, {})
            self.assertEqual(args[:2], ('/usr/bin/systemctl', 'show'))
            self.assertEqual(args[3:], ('--property=LoadState,ActiveState,SubState,UnitFileState',))
            if args[2] == RECOVERY:
                return next(observations)
            return 'LoadState=loaded\nActiveState=active\nSubState=running\nUnitFileState=enabled'
        transaction = upgrade.Upgrade(pathlib.Path('/candidate'), runner=run)
        transaction.queue_check = mock.Mock()
        return transaction, calls

    def test_original_transition_is_not_idle_but_fresh_complete_census_and_queue_can_pass(self):
        transaction, calls = self.transaction([TRANSITION, IDLE])
        output = io.StringIO()
        with mock.patch.object(upgrade.time, 'sleep') as sleep, contextlib.redirect_stderr(output):
            result = transaction.preflight_service_states()
        self.assertEqual(result[RECOVERY]['ActiveState'], 'inactive')
        self.assertEqual(set(result), set(upgrade.PROGRAMS + (upgrade.TIMER, RECOVERY, 'nginx.service')))
        self.assertEqual(sum(call[2] == 'panel.service' for call in calls), 2)
        transaction.queue_check.assert_called_once_with()
        sleep.assert_called_once_with(0.25)
        record = json.loads(output.getvalue())
        self.assertEqual(record['original_observation']['original_output_sha256'], hashlib.sha256(TRANSITION.encode()).hexdigest())
        self.assertEqual(record['original_observation']['properties']['ActiveState'], 'activating')
        self.assertFalse(record['mutating_installer_replay'])
        self.assertIsNone(transaction.backup)
        self.assertEqual(transaction.locks, [])

    def test_actual_active_oneshot_must_be_observed_idle_before_admission(self):
        active = IDLE.replace('inactive', 'active').replace('dead', 'running')
        transaction, calls = self.transaction([active, IDLE])
        with mock.patch.object(upgrade.time, 'sleep'), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(transaction.preflight_service_states()[RECOVERY]['SubState'], 'dead')
        self.assertEqual(sum(call[2] == RECOVERY for call in calls), 2)

    def test_third_busy_observation_refuses_without_fourth_census_or_mutation(self):
        transaction, calls = self.transaction([TRANSITION] * 3)
        with mock.patch.object(upgrade.time, 'sleep') as sleep, contextlib.redirect_stderr(io.StringIO()), self.assertRaises(upgrade.ServiceStateFailure):
            transaction.preflight_service_states()
        self.assertEqual(sum(call[2] == RECOVERY for call in calls), 3)
        self.assertEqual(transaction.queue_check.call_count, 2)
        self.assertEqual(sleep.call_args_list, [mock.call(0.25), mock.call(0.25)])

    def test_mask_failed_unknown_duplicate_incomplete_nonstatic_and_nonidle_pairs_never_wait(self):
        for raw in (TRANSITION.replace('loaded', 'masked'), TRANSITION.replace('activating', 'failed'),
                    TRANSITION.replace('start', 'future'), TRANSITION.replace('static', 'enabled'),
                    TRANSITION + '\nUnitFileState=static', TRANSITION.replace('SubState=start\n', ''),
                    IDLE.replace('dead', 'exited'), TRANSITION.replace('activating', 'reloading')):
            with self.subTest(raw=raw):
                transaction, calls = self.transaction([raw])
                with mock.patch.object(upgrade.time, 'sleep') as sleep, self.assertRaises(upgrade.ServiceStateFailure):
                    transaction.preflight_service_states()
                sleep.assert_not_called()
                transaction.queue_check.assert_not_called()

    def test_other_services_keep_original_fail_closed_state_without_census_retry(self):
        for unit in upgrade.PROGRAMS + (upgrade.TIMER, 'nginx.service'):
            transaction, unused = self.transaction([IDLE])
            original = transaction.run_command
            transaction.run_command = lambda *args, **kwargs: TRANSITION if args[2] == unit else original(*args, **kwargs)
            with mock.patch.object(upgrade.time, 'sleep') as sleep, self.assertRaises(upgrade.ServiceStateFailure) as caught:
                transaction.preflight_service_states()
            self.assertEqual(caught.exception.public_metadata['unit'], unit)
            sleep.assert_not_called()
            transaction.queue_check.assert_not_called()

    def test_unknown_later_state_never_borrows_original_periodic_identity(self):
        transaction, calls = self.transaction([TRANSITION, TRANSITION.replace('loaded', 'masked')])
        with mock.patch.object(upgrade.time, 'sleep') as sleep, contextlib.redirect_stderr(io.StringIO()), self.assertRaises(upgrade.ServiceStateFailure) as caught:
            transaction.preflight_service_states()
        self.assertEqual(caught.exception.public_metadata['properties']['LoadState'], 'masked')
        sleep.assert_called_once_with(0.25)
        transaction.queue_check.assert_called_once_with()

    def test_full_queue_refusal_after_wait_cannot_be_replaced_by_later_idle_service(self):
        for error in (ValueError('busy database queue'), upgrade.CommandFailure('panel-executor', 1, '', 'context deadline exceeded')):
            transaction, calls = self.transaction([TRANSITION, IDLE])
            transaction.queue_check.side_effect = error
            with mock.patch.object(upgrade.time, 'sleep'), contextlib.redirect_stderr(io.StringIO()), self.assertRaises(type(error)) as caught:
                transaction.preflight_service_states()
            self.assertIs(caught.exception, error)
            self.assertEqual(sum(call[2] == RECOVERY for call in calls), 1)

    def test_mutation_or_runtime_lease_phases_cannot_wait(self):
        for changes in ({'backup': pathlib.Path('/owned')}, {'pending_created': True}, {'stopping': True},
                        {'changed': True}, {'locks': [10, 11]}, {'locks': [-1]}, {'layout': 'unknown'}):
            transaction, calls = self.transaction([TRANSITION])
            for key, value in changes.items():
                setattr(transaction, key, value)
            with mock.patch.object(upgrade.time, 'sleep') as sleep, self.assertRaises(upgrade.ServiceStateFailure):
                transaction.preflight_service_states()
            sleep.assert_not_called()
            transaction.queue_check.assert_not_called()

    def test_original_state_reader_has_no_implicit_wait_or_service_action(self):
        transaction, calls = self.transaction([TRANSITION])
        with mock.patch.object(upgrade.time, 'sleep') as sleep, self.assertRaises(upgrade.ServiceStateFailure):
            transaction.state(RECOVERY)
        self.assertEqual(len(calls), 1)
        sleep.assert_not_called()
        with self.assertRaises(ValueError):
            transaction.state('nginx.service', require_recovery_idle=True)
        self.assertEqual(len(calls), 1)


@unittest.skipUnless(sys.platform.startswith('linux') and os.geteuid() == 0, 'actual Root Linux transaction fixture required')
class PeriodicServiceCensusTransactionTests(unittest.TestCase):
    def fixtures(self):
        production = load('census_production_fixtures', 'test_production_upgrade.py')
        development = load('census_development_fixtures', 'test_development_upgrade_safety.py')
        return (production.UpgradeTransactionTests().fixture, development.DevelopmentUpgradeTransactionTests().fixture)

    def test_real_filesystem_both_layouts_wait_before_first_or_second_census_without_service_replay(self):
        for fixture in self.fixtures():
            for occurrence in (1, 2):
                with fixture() as (transaction, runner, root):
                    original = transaction.run_command
                    observed = []
                    def run(*args, **kwargs):
                        if args == ('/usr/bin/systemctl', 'show', RECOVERY, '--property=LoadState,ActiveState,SubState,UnitFileState'):
                            observed.append(len(transaction.locks))
                            if len(observed) == occurrence:
                                self.assertIsNone(transaction.backup)
                                self.assertFalse(transaction.pending_created)
                                return TRANSITION
                        return original(*args, **kwargs)
                    transaction.run_command = run
                    with contextlib.redirect_stderr(io.StringIO()):
                        transaction.run()
                    self.assertTrue(transaction.committed)
                    self.assertIn(occurrence - 1, observed)
                    self.assertFalse(any(call[1] in ('stop', 'start', 'reset-failed') and RECOVERY in call for call in runner.calls))
                    with sqlite3.connect(root / 'var/lib/panel/panel.db') as db:
                        self.assertEqual(db.execute('SELECT value FROM configuration').fetchone(), ('original',))

    def test_real_filesystem_busy_sql_queue_during_wait_refuses_before_backup_or_program_mutation(self):
        for fixture in self.fixtures():
            with fixture() as (transaction, runner, root):
                original = transaction.run_command
                def run(*args, **kwargs):
                    if args == ('/usr/bin/systemctl', 'show', RECOVERY, '--property=LoadState,ActiveState,SubState,UnitFileState'):
                        with sqlite3.connect(root / 'var/lib/panel/panel.db') as db:
                            db.execute("INSERT INTO runtime_jobs VALUES ('late-original', 'running')")
                        return TRANSITION
                    return original(*args, **kwargs)
                transaction.run_command = run
                with contextlib.redirect_stderr(io.StringIO()), self.assertRaisesRegex(ValueError, 'wait for active'):
                    transaction.run()
                self.assertIsNone(transaction.backup)
                self.assertFalse(transaction.pending_created)
                self.assertFalse(transaction.changed)
                self.assertEqual(list((root / 'var/backups/panel/system').iterdir()), [])
                self.assertFalse(any(len(call) > 1 and call[1] in ('stop', 'start', 'reset-failed', 'daemon-reload') for call in runner.calls))
