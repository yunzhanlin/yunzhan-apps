import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {createHash} from 'node:crypto';
const read=p=>readFile(new URL('../'+p,import.meta.url),'utf8');
const sum=value=>createHash('sha256').update(value).digest('hex');

test('Task snapshot patch is independently versioned, preserving the original package and all other 48 non-load-balance catalog identities',async()=>{
 const catalog=JSON.parse(await read('dist/catalog-v1.json'));
 const task=catalog.apps.find(a=>a.id==='task-manager');assert.equal(task.version,'1.2.1');assert.equal(catalog.apps.length,50);
 const other=catalog.apps.filter(a=>!['task-manager','load-balance'].includes(a.id)).sort((a,b)=>a.id.localeCompare(b.id));
 assert.equal(sum(JSON.stringify(other)),'d20234c1fa053a58c7b3390be8926260092765baac464697eebfa3ecb7d6102c');
 const old=await read('dist/apps/task-manager/1.2.0/manifest.json');assert.equal(sum(old),'210dc302db5f1c87915a3f20dc96d5c94232cfbd66da229e50ae30e9c7be0600');
 const current=await read('dist/apps/task-manager/1.2.1/manifest.json');assert.equal(sum(current),task.sha256);
 const manifest=JSON.parse(current),registry=JSON.parse(await read('registry/apps.json'));
 assert.deepEqual(manifest,registry.apps.find(a=>a.id==='task-manager'));
 assert(manifest.summary.includes('需要支持 1.2.1 的签名面板'));assert(manifest.capabilities.some(s=>s.includes('不重新采样或改变权限')));
});

test('Task implementation and all corrected fixtures match exact normal BECJ source without runtime or test overrides',async()=>{
 const index=JSON.parse(await read('panel-integration/source-sha256.json')),release=JSON.parse(await read('panel-integration/release-source-inputs.json'));
 assert.equal(release.frozen_inputs_sha256,'aa555c256b44b62167c3914518602c619e01b69c7c614a70058156fff0d377a3');assert.equal(release.archive_sha256,'9b0cdcf80a1431e735e240fda3ea8a728c067dd2e45d414f511d56310338975b');assert.equal(Object.keys(index.test_overrides??{}).length,0);
 for(const file of ['internal/core/app_modules.go','internal/core/app_modules_test.go','web/src/AppModuleReport.vue','web/src/taskManager.ts','scripts/test-task-manager.mjs','internal/executor/app_load_balance_history_linux_test.go','internal/executor/app_reliability_linux_test.go','internal/executor/app_sync_remote_linux_test.go','internal/executor/app_threat_rotation_linux_test.go','internal/executor/app_threat_transaction_linux_test.go','internal/executor/app_update_linux_test.go']){
  const actual=sum(await read('panel-integration/'+file));assert.equal(index.files[file],actual,file);assert.equal(release.files[file],actual,file);
 }
 const definitions=await read('panel-integration/internal/core/app_modules.go');assert.match(definitions,/case "task-manager":\s+version = "1\.2\.1"/);
 const native=await read('panel-integration/internal/core/app_modules_test.go');assert(native.includes('TestTaskSnapshotReleaseHasIndependentPatchVersion'));
 assert.equal((await read('panel-integration/scripts/test-task-manager.mjs')).match(/^test\(/gm).length,13);
});

test('Task source publication never substitutes for live app update or commercial acceptance',async()=>{
 const contracts=JSON.parse(await read('registry/functional-contracts.json'));
 assert.equal(contracts.commercial_feature_parity_complete,false);assert.equal(contracts.reviewed_normal_release.all_50_commercial,false);assert.equal(contracts.reviewed_normal_release.main_release_delivered,false);
 const task=contracts.apps.find(a=>a.id==='task-manager');assert(task.scenarios.some(s=>s.includes('签名仓库实际更新已独立核对')));assert(task.boundaries.some(s=>s.includes('真实更新不能用面板程序升级代替')));assert.equal(contracts.previous_main_delivery.actual_main_task_update_proof_sha256,'6355284beb0e908f6bd79bd399e4c568ac2e3b96892cddd1f30fc5990f411180');
});
