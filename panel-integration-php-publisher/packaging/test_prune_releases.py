"""Owned temporary release cleanup fixtures; never prune a real installation."""
import contextlib
import fcntl
import importlib.util
import json
import os
import pathlib
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

SPEC = importlib.util.spec_from_file_location('prune_release', pathlib.Path(__file__).with_name('prune-releases.py'))
prune = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(prune)
SOURCE = pathlib.Path(__file__).resolve().parents[1]


class ReleasePruneTests(unittest.TestCase):
    @contextlib.contextmanager
    def fixture(self, journals=True):
        with tempfile.TemporaryDirectory(prefix='panel-own-release-prune-') as directory:
            root = pathlib.Path(directory).resolve()
            releases = root/'opt/panel/releases'
            releases.mkdir(parents=True)
            backups = root/'var/backups/panel/system'
            backups.mkdir(parents=True)
            backups.chmod(0o700)
            versions = {}
            for number in range(1, 7):
                path = releases/f'0.1.0-dev.fixture{number}'
                path.mkdir()
                (path/'program').write_bytes(('owned program '+str(number)).encode())
                os.utime(path, ns=(number*1000000000,number*1000000000))
                versions[number] = path
            (root/'opt/panel/current').symlink_to(versions[6])
            lock = releases/'.release.lock'
            lock.write_bytes(b'do not truncate or rechmod')
            lock.chmod(0o644)
            if journals:
                self.journal(root,4,1,'committed')
                self.journal(root,5,2,'rolled-back')
            yield root, versions

    def journal(self, root, candidate, previous, phase):
        directory=root/'var/backups/panel/system'/f'production-0.1.0-dev.fixture{candidate}'
        directory.mkdir(mode=0o700,exist_ok=True)
        state={'LoadState':'loaded','ActiveState':'active','SubState':'running','UnitFileState':'enabled'}
        record={'format':1,'version':f'0.1.0-dev.fixture{candidate}','previous':str(root/'opt/panel/releases'/f'0.1.0-dev.fixture{previous}'),'phase':phase,'services':{service:dict(state) for service in prune.SERVICES}}
        path=directory/'transaction.json'
        path.write_text(json.dumps(record)+'\n')
        path.chmod(0o600)
        return path

    def execute(self, root, apply=False, output=None):
        transaction=prune.Pruner(root,keep=1)
        try:
            return transaction.execute(apply,output=output or (lambda value: None))
        finally:
            transaction.close()

    def snapshot(self, root):
        result={}
        for path in [root]+sorted(root.rglob('*')):
            info=path.lstat()
            data=os.readlink(path) if path.is_symlink() else path.read_bytes() if path.is_file() else None
            result[path.relative_to(root).as_posix()]=(prune.identity(info),data)
        return result

    def test_preview_is_fully_readonly_and_preserves_all_recovery_references(self):
        with self.fixture() as (root,versions):
            before=self.snapshot(root)
            rows=[]
            self.assertEqual(self.execute(root,output=rows.append),1)
            self.assertIn('would remove 0.1.0-dev.fixture3',rows[0])
            self.assertEqual(self.snapshot(root),before)
            self.assertTrue(all(path.exists() for path in versions.values()))

    def test_explicit_apply_deletes_only_unreferenced_owned_obsolete_program(self):
        with self.fixture() as (root,versions):
            journal_before={path:path.read_bytes() for path in (root/'var/backups/panel/system').rglob('transaction.json')}
            lock=root/'opt/panel/releases/.release.lock'
            lock_before=(prune.identity(lock.stat()),lock.read_bytes())
            self.assertEqual(self.execute(root,True),1)
            self.assertFalse(versions[3].exists())
            self.assertTrue(all(versions[number].exists() for number in (1,2,4,5,6)))
            self.assertEqual({path:path.read_bytes() for path in journal_before},journal_before)
            self.assertEqual((prune.identity(lock.stat()),lock.read_bytes()),lock_before)

    def test_every_known_phase_protects_old_and_candidate_versions(self):
        for phase in sorted(prune.PHASES):
            with self.subTest(phase=phase),self.fixture(False) as (root,versions):
                self.journal(root,4,1,phase)
                transaction=prune.Pruner(root,1)
                try:
                    transaction.acquire(False)
                    self.assertEqual(transaction.refs()[0],{versions[4].name,versions[1].name})
                finally:
                    transaction.close()

    def test_legacy_backup_without_previous_program_reference_retains_every_release(self):
        for kind in ('pre-update-database','development-directory'):
            with self.subTest(kind=kind),self.fixture() as (root,versions):
                base=root/'var/backups/panel/system'
                if kind=='pre-update-database':
                    path=base/'pre-update-0.1.0-dev.fixture5.db';path.write_bytes(b'owned legacy rollback database');path.chmod(0o600)
                else:
                    path=base/'development-0.1.0-dev.fixture5';path.mkdir(mode=0o700)
                before=self.snapshot(root)
                self.assertEqual(self.execute(root,True),0,'legacy backup cannot prove its previous program; do not delete any program version')
                self.assertEqual(self.snapshot(root),before)

    def test_pending_dangling_marker_stage_or_pointer_stage_refuses_without_deletion(self):
        for kind in ('marker','dangling-marker','stage','pointer'):
            with self.subTest(kind=kind),self.fixture() as (root,versions):
                path=root/'opt/panel/releases/.program-upgrade.pending'
                if kind=='stage': path=root/'opt/panel/releases/0.1.0-dev.fixture7.tmp'
                if kind=='pointer': path=root/'opt/panel/current.new'
                if kind=='dangling-marker': path.symlink_to(root/'absent')
                elif kind=='stage': path.mkdir()
                else: path.write_bytes(b'retained interrupted evidence')
                before=self.snapshot(root)
                with self.assertRaises(ValueError): self.execute(root,True)
                self.assertEqual(self.snapshot(root),before)

    def test_journal_link_hardlink_or_public_permissions_refuse_before_deletion(self):
        for kind in ('symlink','hardlink','permissions','directory'):
            with self.subTest(kind=kind),self.fixture() as (root,versions):
                path=root/'var/backups/panel/system/production-0.1.0-dev.fixture4/transaction.json'
                if kind=='symlink':
                    path.unlink();path.symlink_to(root/'unrelated')
                elif kind=='hardlink': os.link(path,path.with_name('second-link'))
                elif kind=='permissions': path.chmod(0o644)
                else: path.parent.chmod(0o755)
                before=self.snapshot(root)
                with self.assertRaises((ValueError,OSError)): self.execute(root,True)
                self.assertEqual(self.snapshot(root),before)

    def test_unknown_duplicate_truncated_or_missing_journal_refuses_before_deletion(self):
        for content in ('{"format":1,"format":1}', '{', '{}', None):
            with self.subTest(content=content),self.fixture() as (root,versions):
                path=root/'var/backups/panel/system/production-0.1.0-dev.fixture4/transaction.json'
                if content is None: path.unlink()
                else: path.write_text(content)
                before=self.snapshot(root)
                with self.assertRaises((ValueError,FileNotFoundError)): self.execute(root,True)
                self.assertEqual(self.snapshot(root),before)

    def test_invalid_reference_phase_format_or_incomplete_service_state_refuses(self):
        for field,value in (('previous','/outside/0.1.0-dev.fixture1'),('phase','unknown'),('phase',[]),('format',True),('services',{})):
            with self.subTest(field=field,value=value),self.fixture() as (root,versions):
                path=root/'var/backups/panel/system/production-0.1.0-dev.fixture4/transaction.json'
                record=json.loads(path.read_text());record[field]=value;path.write_text(json.dumps(record))
                before=self.snapshot(root)
                with self.assertRaises(ValueError): self.execute(root,True)
                self.assertEqual(self.snapshot(root),before)

    def test_missing_previous_release_is_not_permission_to_erase_more_versions(self):
        with self.fixture() as (root,versions):
            versions[1].rename(versions[1].with_name('retained-other-name'))
            before=self.snapshot(root)
            with self.assertRaises(FileNotFoundError): self.execute(root,True)
            self.assertEqual(self.snapshot(root),before)

    def test_linked_hardlinked_or_special_candidate_never_reaches_recursive_delete(self):
        for kind in ('symlink','hardlink','fifo'):
            with self.subTest(kind=kind),self.fixture() as (root,versions):
                path=versions[3]/'unsafe'
                if kind=='symlink': path.symlink_to(root/'var/backups/panel/system')
                elif kind=='hardlink': os.link(versions[3]/'program',path)
                else: os.mkfifo(path)
                # Creating the unsafe child must not make this deliberately
                # obsolete fixture the newest protected release.
                os.utime(versions[3],ns=(3000000000,3000000000))
                with mock.patch.object(prune.shutil,'rmtree',side_effect=AssertionError('unsafe candidate reached deletion')):
                    with self.assertRaises(ValueError): self.execute(root,True)
                self.assertTrue(all(path.exists() for path in versions.values()))

    def test_same_device_nested_bind_mount_inventory_refuses_before_deletion(self):
        with self.fixture() as (root,versions):
            nested=versions[3]/'mounted';nested.mkdir()
            os.utime(versions[3],ns=(3000000000,3000000000))
            before=self.snapshot(root)
            with mock.patch.object(prune.Pruner,'mounted_paths',return_value={nested}):
                with self.assertRaises(ValueError): self.execute(root,True)
            self.assertEqual(self.snapshot(root),before)

    def test_missing_linked_hardlinked_or_world_writable_lock_is_never_created_or_changed(self):
        for kind in ('missing','symlink','hardlink','writable'):
            with self.subTest(kind=kind),self.fixture() as (root,versions):
                path=root/'opt/panel/releases/.release.lock'
                if kind=='missing': path.unlink()
                elif kind=='symlink': path.unlink();path.symlink_to(root/'absent')
                elif kind=='hardlink': os.link(path,path.with_name('lock-second'))
                else: path.chmod(0o666)
                before=self.snapshot(root)
                with self.assertRaises((OSError,ValueError)): self.execute(root,True)
                self.assertEqual(self.snapshot(root),before)

    def test_existing_exclusive_upgrade_lock_refuses_immediately(self):
        with self.fixture() as (root,versions):
            with (root/'opt/panel/releases/.release.lock').open('rb') as lock:
                fcntl.flock(lock.fileno(),fcntl.LOCK_EX|fcntl.LOCK_NB)
                with self.assertRaises(BlockingIOError): self.execute(root,True)
            self.assertTrue(all(path.exists() for path in versions.values()))

    def test_reference_change_after_first_delete_stops_remaining_deletions(self):
        with self.fixture(False) as (root,versions):
            path=self.journal(root,4,1,'committed')
            def change(value):
                if value.startswith('removed '):
                    record=json.loads(path.read_text());record['phase']='rolled-back';path.write_text(json.dumps(record))
            with self.assertRaises(ValueError): self.execute(root,True,change)
            self.assertFalse(versions[5].exists())
            self.assertTrue(all(versions[number].exists() for number in (1,2,3,4,6)))

    def test_pointer_change_after_first_delete_stops_before_new_current_target(self):
        with self.fixture(False) as (root,versions):
            self.journal(root,4,1,'committed')
            def change(value):
                if value.startswith('removed '):
                    current=root/'opt/panel/current';current.unlink();current.symlink_to(versions[2])
            with self.assertRaises(ValueError): self.execute(root,True,change)
            self.assertTrue(versions[2].exists())

    def test_changed_payload_after_plan_is_not_deleted(self):
        with self.fixture() as (root,versions):
            original=prune.Pruner.plan
            def change(transaction):
                result=original(transaction)
                (versions[3]/'program').write_bytes(b'changed after checked plan')
                return result
            with mock.patch.object(prune.Pruner,'plan',change):
                with self.assertRaises(ValueError): self.execute(root,True)
            self.assertTrue(all(path.exists() for path in versions.values()))

    def test_replaced_lock_path_after_plan_never_uses_old_descriptor_as_new_lease(self):
        with self.fixture() as (root,versions):
            original=prune.Pruner.plan
            def change(transaction):
                result=original(transaction)
                path=root/'opt/panel/releases/.release.lock'
                path.rename(path.with_name('retained-original-lock'))
                path.write_bytes(b'foreign unlocked replacement');path.chmod(0o600)
                return result
            with mock.patch.object(prune.Pruner,'plan',change):
                with self.assertRaises(ValueError): self.execute(root,True)
            self.assertTrue(all(path.exists() for path in versions.values()))

    @unittest.skipUnless(os.geteuid()==0,'actual owner mismatch requires a root-owned fixture; policy is not bypassed on nonroot hosts')
    def test_actual_foreign_backup_and_obsolete_payload_owners_refuse_even_as_root(self):
        for target in ('backup','payload'):
            with self.subTest(target=target),self.fixture() as (root,versions):
                path=root/'var/backups/panel/system/production-0.1.0-dev.fixture4/transaction.json' if target=='backup' else versions[3]/'program'
                os.chown(path,12345,12345)
                before=self.snapshot(root)
                with self.assertRaises(ValueError): self.execute(root,True)
                self.assertEqual(self.snapshot(root),before)

    @unittest.skipUnless(os.geteuid()==0 and sys.platform=='linux','actual bind mount classification requires isolated native Linux root acceptance')
    def test_actual_private_bind_mount_refuses_all_deletion(self):
        with self.fixture() as (root,versions):
            source=root/'owned-bind-source';source.mkdir();(source/'sentinel').write_bytes(b'owned native mount fixture')
            target=versions[3]/'mounted';target.mkdir()
            os.utime(versions[3],ns=(3000000000,3000000000))
            mounted=subprocess.run(['/usr/bin/mount','--bind',str(source),str(target)],capture_output=True)
            self.assertEqual(mounted.returncode,0,'native bind mount setup failed; not a passing mount proof')
            try:
                with self.assertRaises(ValueError): self.execute(root,True)
                self.assertTrue(all(path.exists() for path in versions.values()))
                self.assertEqual((source/'sentinel').read_bytes(),b'owned native mount fixture')
            finally:
                unmounted=subprocess.run(['/usr/bin/umount',str(target)],capture_output=True)
                self.assertEqual(unmounted.returncode,0,'own native bind mount must be removed before fixture cleanup')

    def test_bounded_inventory_aborts_and_unknown_directories_are_never_targets(self):
        with self.assertRaises(ValueError): prune.bounded_paths(iter(range(4)),3)
        with self.fixture() as (root,versions):
            unknown=root/'opt/panel/releases/keep-evidence';unknown.mkdir();(unknown/'sentinel').write_bytes(b'owned evidence')
            self.execute(root,True)
            self.assertEqual((unknown/'sentinel').read_bytes(),b'owned evidence')

    def test_actual_shell_entrypoint_is_readonly_and_packager_installer_include_helper(self):
        with self.fixture() as (root,versions):
            before=self.snapshot(root)
            result=subprocess.run(['bash',str(SOURCE/'packaging/prune-releases.sh'),'--root',str(root),'--keep','1'],capture_output=True,text=True)
            self.assertEqual(result.returncode,0,result.stderr)
            self.assertIn('mode=preview',result.stdout)
            self.assertEqual(self.snapshot(root),before)
        builder=(SOURCE/'packaging/build-release.sh').read_text()
        self.assertIn('"$BUILD_ROOT/packaging/prune-releases.py"',builder)
        self.assertIn('prune-releases.sh prune-releases.py first-install.py',builder)
        self.assertIn('"$HERE/prune-releases.py"',(SOURCE/'packaging/install.sh').read_text())
        self.assertNotIn('rm -rf',(SOURCE/'packaging/prune-releases.sh').read_text())


if __name__=='__main__':
    unittest.main()
