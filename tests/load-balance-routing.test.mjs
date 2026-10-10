import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {createHash} from 'node:crypto';
const read=p=>readFile(new URL('../'+p,import.meta.url),'utf8');
test('1.8.2 exports the exact normal frozen routing/status source and mandatory frontend gate',async()=>{
 const index=JSON.parse(await read('panel-integration/source-sha256.json')),release=JSON.parse(await read('panel-integration/release-source-inputs.json'));
 assert.equal(release.frozen_inputs_sha256,'0c09ccd8603afc68d42caed2a2f1c71672cded67d16e9ab888c9fc6dcc7e0fbb');
 assert.equal(release.archive_sha256,'203eddd7f66a7da29e21c3fce42cf56a7322c53ec519171c864199979d06a68c');
 for(const file of ['scripts/test-load-balance-routing.mjs','web/src/loadBalanceRouting.ts','internal/core/load_balance_routing_test.go','internal/executor/app_load_balance_routing_linux.go','internal/executor/app_load_balance_routing_linux_test.go','internal/executor/app_load_balance_active_native_qa_linux_test.go','internal/executor/app_load_balance_status_linux.go','internal/executor/app_load_balance_status_linux_test.go']){
  const body=await read('panel-integration/'+file),sha=createHash('sha256').update(body).digest('hex');
  assert.equal(release.files[file],sha,file);assert.equal(index.files[file],sha,file);
 }
 assert.equal(Object.keys(release.files).filter(f=>/^scripts\/test-[a-z0-9-]+\.mjs$/.test(f)).length,23);
 const build=await read('panel-integration/packaging/build-release.sh');assert.match(build,/test-load-balance-routing\.mjs/);
 const frontend=await read('panel-integration/web/src/loadBalanceRouting.ts');assert.match(frontend,/ENABLE HEALTH ROUTING/);assert.match(frontend,/auto_traffic/);
 const registry=JSON.parse(await read('registry/apps.json')),contracts=JSON.parse(await read('registry/functional-contracts.json'));
 assert.equal(registry.apps.find(a=>a.id==='load-balance').version,'1.8.2');
 const automatic=JSON.parse(await read('dist/apps/load-balance/1.7.0/manifest.json'));assert.equal(automatic.version,'1.7.0');assert.match(automatic.summary,/自动摘除与恢复/);
 const status=await read('panel-integration/internal/executor/app_load_balance_status_linux.go');assert.match(status,/stale \|\| workerError != ""/);assert.match(status,/自动流量已明确启用/);assert.match(status,/LoadBalanceHealthRoutingVersion/);
 const manager=await read('panel-integration/web/src/AppModuleManager.vue');assert.match(manager,/<span>故障节点自动摘除与恢复<\/span>/);assert.doesNotMatch(manager,/保存后只观测、不自动改动流量/);
 const old=JSON.parse(await read('dist/apps/load-balance/1.6.0/manifest.json'));assert.equal(old.version,'1.6.0');assert.match(old.summary,/只观测/);
 assert.equal(contracts.commercial_feature_parity_complete,false);
});
