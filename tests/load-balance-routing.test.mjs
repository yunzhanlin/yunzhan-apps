import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {createHash} from 'node:crypto';
const read=p=>readFile(new URL('../'+p,import.meta.url),'utf8');
test('1.7 exports the exact normal frozen routing source and mandatory frontend gate',async()=>{
 const index=JSON.parse(await read('panel-integration/source-sha256.json')),release=JSON.parse(await read('panel-integration/release-source-inputs.json'));
 assert.equal(release.frozen_inputs_sha256,'c8e4764bb6eb8b046979509f084ae2d961f33f74b96c5d6e0fbe85f4be73ee0c');
 assert.equal(release.archive_sha256,'638b6f374a429bf82b5c0e694ce83b9fbb0a68abe2b9c842648d9a3716672f09');
 for(const file of ['scripts/test-load-balance-routing.mjs','web/src/loadBalanceRouting.ts','internal/core/load_balance_routing_test.go','internal/executor/app_load_balance_routing_linux.go','internal/executor/app_load_balance_routing_linux_test.go','internal/executor/app_load_balance_active_native_qa_linux_test.go']){
  const body=await read('panel-integration/'+file),sha=createHash('sha256').update(body).digest('hex');
  assert.equal(release.files[file],sha,file);assert.equal(index.files[file],sha,file);
 }
 assert.equal(Object.keys(release.files).filter(f=>/^scripts\/test-[a-z0-9-]+\.mjs$/.test(f)).length,17);
 const build=await read('panel-integration/packaging/build-release.sh');assert.match(build,/test-load-balance-routing\.mjs/);
 const frontend=await read('panel-integration/web/src/loadBalanceRouting.ts');assert.match(frontend,/ENABLE HEALTH ROUTING/);assert.match(frontend,/auto_traffic/);
 const registry=JSON.parse(await read('registry/apps.json')),contracts=JSON.parse(await read('registry/functional-contracts.json'));
 assert.equal(registry.apps.find(a=>a.id==='load-balance').version,'1.7.0');
 const old=JSON.parse(await read('dist/apps/load-balance/1.6.0/manifest.json'));assert.equal(old.version,'1.6.0');assert.match(old.summary,/只观测/);
 assert.equal(contracts.commercial_feature_parity_complete,false);
});
