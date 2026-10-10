import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
const read=p=>readFile(new URL('../'+p,import.meta.url),'utf8');
test('1.9 publishes reviewed backup migration without rewriting immutable readonly releases',async()=>{
 const registry=JSON.parse(await read('registry/apps.json')),contracts=JSON.parse(await read('registry/functional-contracts.json'));
 const app=registry.apps.find(a=>a.id==='files-sync'),contract=contracts.apps.find(a=>a.id===app.id);
 assert.equal(app.version,'1.9.0');assert.match(app.summary,/完整摘要与精确确认/);assert.match(app.summary,/硬链接不是独立不可变快照/);assert.match(app.summary,/512 份、1 GiB 逻辑字节/);
 assert.equal(contracts.commercial_feature_parity_complete,false);assert(contract.gaps.length>0);
 assert(contract.scenarios.some(s=>s.includes('50 个原生文件同步用例')&&s.includes('不是 50 项应用')));
 assert(contract.scenarios.some(s=>s.includes('chmod 前')&&s.includes('SIGKILL')));
 assert(contract.boundaries.some(s=>s.includes('content_verified=false')));assert(contract.boundaries.some(s=>s.includes('RENAME_NOREPLACE')&&s.includes('不防御')));
 const old=JSON.parse(await read('dist/apps/files-sync/1.8.1/manifest.json'));assert.equal(old.version,'1.8.1');assert.match(old.summary,/受控归档尚未提供/);
});
test('closed archive handlers persist original identity and fail closed across partial native mkdir and rename',async()=>{
 const source=await read('panel-integration/internal/executor/app_sync_remote_backup_archive_linux.go');
 assert.match(source,/remoteBackupArchiveMax = 512/);assert.match(source,/remoteBackupArchiveBytes int64 = 1 << 30/);
 const dispatch=await read('panel-integration/internal/executor/app_sync_remote_linux.go');
 for(const action of ['remote-backup-preview','remote-backup-archive','archive-remote-backup','recover-remote-backup'])assert(dispatch.includes('"'+action+'"'),action);
 for(const action of ['remote-backup-archive','archive-remote-backup','recover-remote-backup'])assert(source.includes('"'+action+'"'),action);
 for(const name of ['remoteBackupArchiveInput','remoteBackupSnapshotMatches','remoteBackupArchivePending','remoteBackupArchiveIdle','remoteBackupPreparingDirectory','remoteBackupArchiveInventoryChild'])assert(source.includes(name));
 assert.match(source,/State: "prepared"/);assert.match(source,/r.State = "reserved"/);assert.match(source,/r.State = "committed"/);assert.match(source,/c.Rename\(source, destination\)/);
 assert.doesNotMatch(source,/\.Remove\(|\.RemoveAll\(|\.PosixRename\(|exec.Command\(/);
 assert.match(source,/"content_verified": false/);assert.match(source,/"replayed": true, "remote_files_changed": false/);
 const fixtures=await read('panel-integration/internal/executor/app_sync_remote_backup_archive_linux_test.go');
 for(const name of ['ActualTransferReplayAndPreservation','ClosedInputsIdleAndStaleContent','UnsafeNamespacesAndCapacity','ExternalMutationAfterCommit','LogicalByteCapacity','TrueMidMoveKill','TruePreparedKill'])assert(fixtures.includes('TestRemoteSyncBackupArchive'+name));
 const core=await read('panel-integration/internal/core/app_module_workspace_test.go');assert.match(core,/archive-remote-backup/);assert.match(core,/recover-remote-backup/);
});
test('normal frozen build includes archive frontend input and recovery gates',async()=>{
 const build=await read('panel-integration/packaging/build-release.sh'),frontend=await read('panel-integration/web/src/remoteBackupArchive.ts');
 assert.match(build,/test-remote-backup-archive\.mjs/);assert.match(frontend,/limit<1\|\|limit>32/);assert.match(frontend,/confirm:''/);assert.match(frontend,/RECOVER/);
 const index=JSON.parse(await read('panel-integration/source-sha256.json')),release=JSON.parse(await read('panel-integration/release-source-inputs.json'));
 assert.equal(release.frozen_inputs_sha256,'6c58f44564b3fc6e060b5583a401d966b4e0251d97ff0adbad13e2335e5e3d63');
 assert.equal(release.archive_sha256,'c47e520887db6b29d3ab373a73d699eb3b9fd39adcaf98cbbd365e6412d3f3cb');
 for(const file of ['scripts/test-remote-backup-archive.mjs','internal/executor/app_sync_remote_backup_archive_linux.go','internal/executor/app_sync_remote_backup_archive_linux_test.go','web/src/remoteBackupArchive.ts']){assert.match(release.files[file],/^[0-9a-f]{64}$/);assert.equal(release.files[file],index.files[file]);}
 const gates=Object.keys(release.files).filter(f=>/^scripts\/test-[a-z0-9-]+\.mjs$/.test(f));assert.equal(gates.length,16);
});
