import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
const read=p=>readFile(new URL('../'+p,import.meta.url),'utf8');
test('actual remote capacity is read-only, bounded, and rejects unknown metadata',async()=>{
 const source=await read('panel-integration/internal/executor/app_sync_remote_backups_linux.go');
 assert.match(source,/remoteBackupTransactions = 512/);assert.match(source,/remoteBackupBytes int64 = 256 << 20/);assert.match(source,/remoteBackupReserve int64 = 16 << 20/);
 assert.match(source,/attrs.UID != owner/);assert.match(source,/a.UID != owner/);assert.match(source,/remoteBackupInput/);assert.match(source,/reflect.DeepEqual/);assert.match(source,/cp.Pending/);
 assert.doesNotMatch(source,/\.Mkdir\(|\.Remove\(|\.Rename\(|\.Write\(|\.Read\(|exec.Command/);
 assert.match(source,/remote_files_changed.*false/);
});
test('capacity admission uses the same complete inventory rather than hiding full namespaces',async()=>{
 const source=await read('panel-integration/internal/executor/app_sync_remote_jobs_linux.go');
 assert.match(source,/remoteBackupInventory/);assert.match(source,/len\(entries\) >= remoteBackupTransactions/);assert.match(source,/remoteBackupBytes-remoteBackupReserve/);
 const fixture=await read('panel-integration/internal/executor/app_sync_remote_backups_linux_test.go');
 for(const name of ['ActualTransfersReadOnlyAndPrivateContent','ExactlyFullAndOversizedNamespace','SparseByteQuotaAndUnsafeEntries','ClosedInputsAndPendingRecovery'])assert(fixture.includes('TestRemoteSyncBackups'+name));
});
test('normal signed source pins the new mandatory frontend capacity regression gate',async()=>{
 const manager=await read('panel-integration/web/src/AppModuleManager.vue'),build=await read('panel-integration/packaging/build-release.sh');
 assert.match(manager,/v-model.number="form\[field.key\]"/);assert.match(manager,/:max="field.key === 'limit' \? 32 : 512"/);assert.match(manager,/remoteBackupBody/);
 assert.match(build,/test-remote-sync-backups\.mjs/);
 const index=JSON.parse(await read('panel-integration/source-sha256.json')),release=JSON.parse(await read('panel-integration/release-source-inputs.json'));
 assert.equal(release.files['scripts/test-remote-sync-backups.mjs'],index.files['scripts/test-remote-sync-backups.mjs']);assert.match(release.files['scripts/test-remote-sync-backups.mjs'],/^[0-9a-f]{64}$/);
});
test('immutable 1.8.1 readonly package remains distinct from current archive delivery',async()=>{
 const registry=JSON.parse(await read('registry/apps.json')),contracts=JSON.parse(await read('registry/functional-contracts.json'));
 const app=registry.apps.find(a=>a.id==='files-sync'),contract=contracts.apps.find(a=>a.id===app.id);
 assert.equal(app.version,'1.9.0');assert(app.capabilities.some(x=>x.includes('只读实际备份事务')));assert.equal(contracts.commercial_feature_parity_complete,false);
 assert(contract.scenarios.some(x=>x.includes('43')&&x.includes('稀疏')));assert(contract.scenarios.some(x=>x.includes('420')&&x.includes('不代替')));
 assert(contract.boundaries.some(x=>x.includes('逻辑字节')&&x.includes('硬链接')));assert(contract.gaps.some(x=>x.includes('远端事务')&&x.includes('独立不可变快照')));
 const readonly=JSON.parse(await read('dist/apps/files-sync/1.8.1/manifest.json'));assert.equal(readonly.version,'1.8.1');assert.match(readonly.summary,/受控归档尚未提供/);
 const old=JSON.parse(await read('dist/apps/files-sync/1.8.0/manifest.json'));assert.equal(old.version,'1.8.0');assert(!old.capabilities.some(x=>x.includes('只读实际备份事务')));
});
