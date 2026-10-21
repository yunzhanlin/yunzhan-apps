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


def periodic_error(**changes):
    record = {'format':1,'kind':'native-program-job-refusal-v1',
              'unit':'panel-mysql-overwrite-recovery.service','job_id':'538093',
              'job_type':'start','job_state':'running','inventory_sha256':'a'*64}
    record.update(changes)
    return upgrade.CommandFailure('/owned/panel-executor',1,'',
                                  '2026/10/21 02:54:00 native program operation is queued; upgrade refused\n'+json.dumps(record)+'\n')


class PeriodicAdmissionPolicyTests(unittest.TestCase):
    def test_only_complete_original_fixed_periodic_start_observations_are_eligible(self):
        for state in ('running','waiting'):
            self.assertTrue(upgrade.original_periodic_recovery_can_be_observed_again(periodic_error(job_state=state)))
        for active, sub in [('activating','condition'),('activating','start'),('active','running')]:
            record={'format':1,'kind':'native-program-unit-refusal-v1','unit':'panel-mysql-overwrite-recovery.service','load_state':'loaded','active_state':active,'sub_state':sub,'inventory_sha256':'b'*64}
            error=upgrade.CommandFailure('panel-executor',1,'','native program operation is active, failed or transitional; upgrade refused\n'+json.dumps(record))
            self.assertTrue(upgrade.original_periodic_recovery_can_be_observed_again(error))

    def test_legacy_other_jobs_partial_duplicate_unknown_failed_or_aliased_output_never_waits(self):
        errors=[periodic_error(unit='panel-mysql-job@123.service'),periodic_error(job_type='stop'),periodic_error(job_state='failed'),periodic_error(job_id='01'),periodic_error(format=True),periodic_error(extra='unknown')]
        original=periodic_error();text=original.output['stderr']['text']
        errors.extend([upgrade.CommandFailure('panel-executor',1,'','native program operation is queued; upgrade refused'),upgrade.CommandFailure('panel-executor',1,'not-empty',text),upgrade.CommandFailure('panel-executor',2,'',text),upgrade.CommandFailure('other',1,'',text),upgrade.CommandFailure('panel-executor',1,'',text+'extra'),upgrade.CommandFailure('panel-executor',1,'',text.replace('"format": 1','"format": 1, "format": 1'))])
        for load,active,sub in [('loaded','failed','failed'),('masked','activating','start'),('loaded','active','exited'),('loaded','inactive','dead'),('loaded','activating','future')]:
            value={'format':1,'kind':'native-program-unit-refusal-v1','unit':'panel-mysql-overwrite-recovery.service','load_state':load,'active_state':active,'sub_state':sub,'inventory_sha256':'b'*64}
            errors.append(upgrade.CommandFailure('panel-executor',1,'','native program operation is active, failed or transitional; upgrade refused\n'+json.dumps(value)))
        for error in errors:
            self.assertFalse(upgrade.original_periodic_recovery_can_be_observed_again(error))

    def test_two_readonly_rechecks_require_complete_current_success_and_log_each_original_hash(self):
        transaction=upgrade.Upgrade(pathlib.Path('/candidate'));first=periodic_error();second=periodic_error(job_id='538094')
        transaction.queue_check=mock.Mock(side_effect=[first,second,None]);output=__import__('io').StringIO()
        with mock.patch.object(upgrade.time,'sleep')as sleep,contextlib.redirect_stderr(output):
            transaction.preflight_queue_check()
        self.assertEqual(transaction.queue_check.call_count,3);self.assertEqual(sleep.call_args_list,[mock.call(0.25),mock.call(0.25)])
        records=[json.loads(line)for line in output.getvalue().splitlines()];self.assertEqual([r['readonly_recheck']for r in records],[1,2])
        for record,error in zip(records,[first,second]):
            self.assertEqual(record['original_observation'],upgrade.public_queue_refusal_diagnostic(error));self.assertFalse(record['mutating_installer_replay'])
        self.assertNotIn('538093',output.getvalue());self.assertNotIn('panel-mysql-overwrite-recovery.service',output.getvalue())

    def test_still_busy_third_original_refusal_is_raised_without_fourth_read_or_mutation(self):
        transaction=upgrade.Upgrade(pathlib.Path('/candidate'));errors=[periodic_error(job_id=str(100+x))for x in range(3)];transaction.queue_check=mock.Mock(side_effect=errors)
        with mock.patch.object(upgrade.time,'sleep')as sleep,contextlib.redirect_stderr(__import__('io').StringIO()),self.assertRaises(upgrade.CommandFailure)as caught:
            transaction.preflight_queue_check()
        self.assertIs(caught.exception,errors[-1]);self.assertEqual(transaction.queue_check.call_count,3);self.assertEqual(sleep.call_count,2);self.assertIsNone(transaction.backup);self.assertFalse(transaction.stopping)

    def test_later_unknown_or_failed_observation_aborts_immediately_without_borrowing_earlier_identity(self):
        for later in (periodic_error(unit='panel-compose-recovery.service'),upgrade.CommandFailure('panel-executor',1,'','context deadline exceeded'),ValueError('changed identity')):
            transaction=upgrade.Upgrade(pathlib.Path('/candidate'));transaction.queue_check=mock.Mock(side_effect=[periodic_error(),later])
            with mock.patch.object(upgrade.time,'sleep')as sleep,contextlib.redirect_stderr(__import__('io').StringIO()),self.assertRaises(type(later))as caught:
                transaction.preflight_queue_check()
            self.assertIs(caught.exception,later);self.assertEqual(transaction.queue_check.call_count,2);sleep.assert_called_once_with(0.25)

    def test_backup_pending_runtime_lease_or_changed_programs_never_use_admission_rechecks(self):
        for changes in ({'backup':pathlib.Path('/owned')},{'pending_created':True},{'stopping':True},{'changed':True},{'locks':[10,11]},{'locks':[-1]}):
            transaction=upgrade.Upgrade(pathlib.Path('/candidate'))
            for key,value in changes.items():setattr(transaction,key,value)
            error=periodic_error();transaction.queue_check=mock.Mock(side_effect=error)
            with mock.patch.object(upgrade.time,'sleep')as sleep,self.assertRaises(upgrade.CommandFailure)as caught:transaction.preflight_queue_check()
            self.assertIs(caught.exception,error);self.assertEqual(transaction.queue_check.call_count,1);sleep.assert_not_called()

    def test_non_command_failures_and_unclassified_deadlines_are_never_retried(self):
        for error in (RuntimeError('unavailable'),ValueError('unsafe'),subprocess.TimeoutExpired('fixed-reader',5),upgrade.CommandFailure('panel-executor',1,'','context deadline exceeded')):
            transaction=upgrade.Upgrade(pathlib.Path('/candidate'));transaction.queue_check=mock.Mock(side_effect=error)
            with mock.patch.object(upgrade.time,'sleep')as sleep,self.assertRaises(type(error))as caught:transaction.preflight_queue_check()
            self.assertIs(caught.exception,error);self.assertEqual(transaction.queue_check.call_count,1);sleep.assert_not_called()

    def test_initial_readonly_admission_creates_no_backup_lock_marker_or_file(self):
        with tempfile.TemporaryDirectory()as temporary:
            root=pathlib.Path(temporary).resolve();original=root/'original';original.write_bytes(b'unchanged');before=(original.stat().st_ino,original.stat().st_mode,original.read_bytes())
            transaction=upgrade.Upgrade(root,root);transaction.queue_check=mock.Mock(side_effect=[periodic_error(),None])
            with mock.patch.object(upgrade.time,'sleep'),contextlib.redirect_stderr(__import__('io').StringIO()):transaction.preflight_queue_check()
            self.assertEqual(list(root.iterdir()),[original]);self.assertEqual((original.stat().st_ino,original.stat().st_mode,original.read_bytes()),before);self.assertEqual(transaction.locks,[]);self.assertIsNone(transaction.backup)


class DiagnosticPolicyTests(unittest.TestCase):
    def test_original_transitional_service_is_identified_without_retry_or_raw_output(self):
        raw = 'LoadState=loaded\nActiveState=activating\nSubState=start\nUnitFileState=static'
        run = mock.Mock(return_value=raw)
        transaction = upgrade.Upgrade(pathlib.Path('/candidate'), runner=run)
        with self.assertRaises(upgrade.ServiceStateFailure) as caught:
            transaction.state('panel-mysql-overwrite-recovery.service')
        value = upgrade.public_service_refusal_diagnostic(caught.exception)
        self.assertEqual(str(caught.exception), 'service has a masked, failed, transitional or unsupported state')
        self.assertEqual(value['unit'], 'panel-mysql-overwrite-recovery.service')
        self.assertEqual(value['properties']['ActiveState'], 'activating')
        self.assertEqual(value['original_output_sha256'], hashlib.sha256(raw.encode()).hexdigest())
        self.assertFalse(value['retry_or_state_exemption']); self.assertTrue(value['original_observation_only'])
        run.assert_called_once_with('/usr/bin/systemctl', 'show', 'panel-mysql-overwrite-recovery.service', '--property=LoadState,ActiveState,SubState,UnitFileState')

    def test_private_or_malformed_service_fields_never_leak_or_become_a_valid_state(self):
        raw = 'LoadState=loaded\nActiveState=private-fixture\nSubState=private-fixture\nUnitFileState=private-fixture'
        transaction = upgrade.Upgrade(pathlib.Path('/candidate'), runner=mock.Mock(return_value=raw))
        with self.assertRaises(upgrade.ServiceStateFailure) as caught: transaction.state('private-unit-fixture')
        value = upgrade.public_service_refusal_diagnostic(caught.exception)
        self.assertEqual(value['unit'], 'unrecognized'); self.assertNotIn('private', json.dumps(value))
        valid = 'LoadState=loaded\nActiveState=active\nSubState=running\nUnitFileState=enabled'
        for malformed in (valid+'\nUnitFileState=disabled', valid+'\nprivate-fixture', valid.replace('SubState=running','private-fixture'), 'x'*4097):
            transaction.run_command = mock.Mock(return_value=malformed)
            with self.assertRaises(upgrade.ServiceStateFailure) as caught: transaction.state('panel.service')
            self.assertNotIn('private', json.dumps(upgrade.public_service_refusal_diagnostic(caught.exception)))
            transaction.run_command.assert_called_once()

    def test_valid_service_observation_and_legacy_value_errors_are_not_reclassified(self):
        raw = 'LoadState=loaded\nActiveState=active\nSubState=running\nUnitFileState=enabled'
        run = mock.Mock(return_value=raw); transaction = upgrade.Upgrade(pathlib.Path('/candidate'), runner=run)
        self.assertEqual(transaction.state('panel.service'), dict(line.split('=',1) for line in raw.splitlines()))
        self.assertIsNone(upgrade.public_service_refusal_diagnostic(ValueError('service has a masked, failed, transitional or unsupported state')))

    def test_development_CLI_preserves_the_original_typed_refusal_and_closed_failure_exit(self):
        spec = importlib.util.spec_from_file_location('development_diagnostic_fixture', pathlib.Path(__file__).with_name('development-upgrade.py'))
        development = importlib.util.module_from_spec(spec); spec.loader.exec_module(development)
        error = development.production.ServiceStateFailure('panel.service','LoadState=masked',{'LoadState':'masked'})
        transaction = mock.Mock(); transaction.preflight.side_effect = error
        output = __import__('io').StringIO()
        with mock.patch.object(development.sys,'argv',['development-upgrade.py','check','/candidate']), mock.patch.object(development.os,'geteuid',return_value=0), mock.patch.object(development,'DevelopmentUpgrade',return_value=transaction), mock.patch.object(development.signal,'signal'), contextlib.redirect_stderr(output):
            with self.assertRaises(SystemExit) as stopped: development.main()
        self.assertEqual(stopped.exception.code,1);lines=output.getvalue().splitlines()
        self.assertEqual(json.loads(lines[0])['unit'],'panel.service');self.assertIn('development upgrade failed: service has a masked',lines[1])
        transaction.preflight.assert_called_once();transaction.rollback.assert_called_once();transaction.close.assert_called_once();transaction.run.assert_not_called()

    def test_public_metadata_preserves_exact_original_hashes_without_any_child_text(self):
        raw = 'fixture-private-output 字' * 1000
        error = upgrade.CommandFailure('/private/panel-executor', 1, raw, 'private credential fixture')
        value = upgrade.public_queue_refusal_diagnostic(error)
        encoded = json.dumps(value)
        self.assertEqual(value['reason_code'], 'unclassified-original-refusal')
        self.assertTrue(value['original_child_only']); self.assertFalse(value['retry_or_queue_exemption'])
        self.assertEqual(value['exit'], 1)
        self.assertEqual(value['output']['stdout']['sha256'], hashlib.sha256(raw.encode()).hexdigest())
        self.assertEqual(value['output']['stdout']['bytes'], len(raw.encode()))
        self.assertNotIn('private', encoded); self.assertNotIn('text', value['output']['stderr'])
        self.assertNotIn('args_received', value)

    def test_only_exact_complete_fixed_source_messages_receive_reason_codes(self):
        fixed = {
            'context deadline exceeded': 'reader-deadline',
            'native program unit inventory cannot be verified': 'native-unit-inventory-unavailable',
            'native program pending jobs cannot be verified': 'native-job-inventory-unavailable',
            'native program operation is active, failed or transitional; upgrade refused': 'native-operation-not-closed',
            'program queue inventory changed; not a drain proof': 'queue-changed-during-read',
        }
        source = (pathlib.Path(__file__).parents[1] / 'internal/executor/program_upgrade_queues_linux.go').read_text()
        for text, code in fixed.items():
            if code != 'reader-deadline': self.assertIn('"' + text + '"', source)
            for prefix in ('', '2026/10/19 11:24:05 '):
                with self.subTest(text=text, prefix=prefix):
                    error = upgrade.CommandFailure('panel-executor', 1, '', prefix + text + '\n')
                    self.assertEqual(upgrade.public_queue_refusal_diagnostic(error)['reason_code'], code)
            for private in (text + ' secret', text + '\nsecret', 'secret\n' + text, text + '\n\n', text + '\r\n', text * 500):
                self.assertEqual(upgrade.public_queue_refusal_diagnostic(upgrade.CommandFailure('panel-executor', 1, '', private))['reason_code'], 'unclassified-original-refusal')

    def test_diagnostic_has_no_filesystem_service_or_command_side_effects(self):
        error = upgrade.CommandFailure('panel-executor', 1, '', 'context deadline exceeded')
        with mock.patch.object(upgrade.os, 'open', side_effect=AssertionError('write')), mock.patch.object(upgrade.subprocess, 'run', side_effect=AssertionError('retry')):
            self.assertEqual(upgrade.public_queue_refusal_diagnostic(error)['reason_code'], 'reader-deadline')
        self.assertIsNone(upgrade.public_queue_refusal_diagnostic(RuntimeError('fixture')))
        self.assertIsNone(upgrade.public_queue_refusal_diagnostic(upgrade.CommandFailure('other-program', 1, '', 'context deadline exceeded')))

    def test_closed_original_native_inventory_is_private_and_never_a_retry_or_admission_exemption(self):
        message = 'native program operation is active, failed or transitional; upgrade refused'
        original = {'format':1, 'kind':'native-program-unit-refusal-v1', 'unit':'panel-mysql-overwrite-recovery.service', 'load_state':'loaded', 'active_state':'activating', 'sub_state':'start', 'inventory_sha256':'a'*64}
        raw = message + '\n' + json.dumps(original) + '\n'
        error = upgrade.CommandFailure('panel-executor', 1, '', '2026/10/21 07:00:00 ' + raw)
        with mock.patch.object(upgrade.os, 'open', side_effect=AssertionError('write')), mock.patch.object(upgrade.subprocess, 'run', side_effect=AssertionError('reread')):
            value = upgrade.public_queue_refusal_diagnostic(error)
        self.assertEqual(value['reason_code'], 'native-operation-not-closed')
        self.assertTrue(value['original_child_only']); self.assertFalse(value['retry_or_queue_exemption'])
        self.assertNotIn('unit', value); self.assertNotIn('activating', json.dumps(value)); self.assertEqual(error.output['stderr']['text'], '2026/10/21 07:00:00 ' + raw)
        job = {'format':1, 'kind':'native-program-job-refusal-v1', 'unit':original['unit'], 'job_id':'538093', 'job_type':'start', 'job_state':'running', 'inventory_sha256':'b'*64}
        text = 'native program operation is queued; upgrade refused\n' + json.dumps(job)
        self.assertEqual(upgrade.original_native_queue_observation_reason(text), 'native-operation-queued')

    def test_native_original_inventory_parser_rejects_unknown_duplicate_mixed_and_noncanonical_data(self):
        message = 'native program operation is active, failed or transitional; upgrade refused'
        original = {'format':1, 'kind':'native-program-unit-refusal-v1', 'unit':'panel-mysql-overwrite-recovery.service', 'load_state':'loaded', 'active_state':'activating', 'sub_state':'start', 'inventory_sha256':'a'*64}
        for change in ({'format':True},{'format':2},{'unit':'/etc/private'},{'active_state':'active\nsecret'},{'inventory_sha256':'caller-key'},{'kind':'future'},{'job_id':'1'}):
            text = message + '\n' + json.dumps(dict(original, **change))
            self.assertIsNone(upgrade.original_native_queue_observation_reason(text))
        encoded = json.dumps(original)
        for text in (message+'\n'+encoded+'\n', message+'\n'+encoded+'\nsecret', message+'\n'+encoded[:-1]+',"format":1}', 'native program operation is queued; upgrade refused\n'+encoded):
            self.assertIsNone(upgrade.original_native_queue_observation_reason(text))
        job = {'format':1,'kind':'native-program-job-refusal-v1','unit':original['unit'],'job_id':'538093','job_type':'start','job_state':'running','inventory_sha256':'b'*64}
        for identity in ('0','01','-1','18446744073709551616'):
            text = 'native program operation is queued; upgrade refused\n'+json.dumps(dict(job,job_id=identity))
            self.assertIsNone(upgrade.original_native_queue_observation_reason(text))

    def test_cli_reports_original_metadata_without_replacing_the_original_refusal(self):
        error = upgrade.CommandFailure('/private/panel-executor', 1, '', 'context deadline exceeded')
        transaction = mock.Mock()
        transaction.preflight.side_effect = error
        output = __import__('io').StringIO()
        with mock.patch.object(upgrade.sys, 'argv', ['upgrade-release.py','check','/candidate']), mock.patch.object(upgrade.os, 'geteuid', return_value=0), mock.patch.object(upgrade, 'Upgrade', return_value=transaction), mock.patch.object(upgrade.signal, 'signal'), contextlib.redirect_stderr(output):
            with self.assertRaises(SystemExit) as stopped: upgrade.main()
        self.assertEqual(stopped.exception.code, 1)
        lines = output.getvalue().splitlines(); metadata = json.loads(lines[0])
        self.assertEqual(metadata['reason_code'], 'reader-deadline')
        self.assertEqual(lines[1], 'production upgrade failed: command failed: panel-executor 1')
        transaction.preflight.assert_called_once(); transaction.rollback.assert_called_once(); transaction.close.assert_called_once()
        transaction.run.assert_not_called()

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
