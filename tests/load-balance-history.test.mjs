import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {createHash} from 'node:crypto';
const read=p=>readFile(new URL('../'+p,import.meta.url),'utf8');
test('1.8.0 archive and listener repair are exact signed frozen source, with prior package immutable',async()=>{
 const index=JSON.parse(await read('panel-integration/source-sha256.json')),release=JSON.parse(await read('panel-integration/release-source-inputs.json'));
 assert.equal(release.frozen_inputs_sha256,'3da26d511c4f0c80246e43977f8c29a03f5243e1495a8f9e7cb5840bce435e16');
 assert.equal(release.archive_sha256,'586b8d26c959ad77653038cfc508613ab8bb49c33c4e9e97cf9356c7428933cc');
 for(const file of ['internal/core/load_balance_history.go','internal/core/load_balance_history_test.go','internal/executor/app_load_balance_history_linux.go','internal/executor/app_load_balance_history_linux_test.go','web/src/loadBalanceTransactions.ts','scripts/test-load-balance-transactions.mjs','internal/executor/waf_reload_generation_linux.go','internal/executor/waf_reload_generation_linux_test.go']){
  const sha=createHash('sha256').update(await read('panel-integration/'+file)).digest('hex');assert.equal(release.files[file],sha,file);assert.equal(index.files[file],sha,file);
 }
 assert.equal(Object.keys(index.files).length,974);assert.equal(Object.keys(release.files).filter(f=>/^scripts\/test-[a-z0-9-]+\.mjs$/.test(f)).length,18);
 const native=await read('panel-integration/internal/executor/app_load_balance_history_linux.go');assert.match(native,/RENAME_NOREPLACE/);assert.match(native,/loadBalanceHealthVersion\(\) != "1\.8\.0"/);
 const worker=await read('panel-integration/internal/executor/waf_reload_generation_linux.go');assert.match(worker,/workerSocketReadError/);assert.match(worker,/errors\.Is\(readErr, os\.ErrPermission\)/);
 const old=JSON.parse(await read('dist/apps/load-balance/1.7.1/manifest.json'));assert.equal(old.version,'1.7.1');assert(!old.capabilities.some(s=>s.includes('私有归档')));
 const registry=JSON.parse(await read('registry/apps.json')),contracts=JSON.parse(await read('registry/functional-contracts.json'));assert.equal(registry.apps.find(a=>a.id==='load-balance').version,'1.8.0');assert.equal(contracts.commercial_feature_parity_complete,false);
});
