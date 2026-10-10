import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {createHash} from 'node:crypto';
const read=p=>readFile(new URL('../'+p,import.meta.url),'utf8');
test('1.8.2 workspace isolation and archive interlocks are exact signed frozen source, with prior packages immutable',async()=>{
 const index=JSON.parse(await read('panel-integration/source-sha256.json')),release=JSON.parse(await read('panel-integration/release-source-inputs.json'));
 assert.equal(release.frozen_inputs_sha256,'0f7939250e83a31326c248908d07deb28fdfc6877f258fffa520bc2b84844a61');
 assert.equal(release.archive_sha256,'df6ca0092e0ce9fade0c9ee566937033da0c0cc4446c6c8d4a398358f013f71f');
 for(const file of ['internal/core/load_balance_history.go','internal/core/load_balance_history_test.go','internal/executor/app_load_balance_history_linux.go','internal/executor/app_load_balance_history_linux_test.go','web/src/loadBalanceTransactions.ts','scripts/test-load-balance-transactions.mjs','internal/executor/waf_reload_generation_linux.go','internal/executor/waf_reload_generation_linux_test.go']){
  const sha=createHash('sha256').update(await read('panel-integration/'+file)).digest('hex');assert.equal(release.files[file],sha,file);assert.equal(index.files[file],sha,file);
 }
 assert.equal(Object.keys(index.files).length,984);assert.equal(Object.keys(release.files).filter(f=>/^scripts\/test-[a-z0-9-]+\.mjs$/.test(f)).length,20);
 const native=await read('panel-integration/internal/executor/app_load_balance_history_linux.go');assert.match(native,/RENAME_NOREPLACE/);assert.match(native,/!core\.LoadBalanceHistoryVersion\(s\.loadBalanceHealthVersion\(\)\)/);assert.match(native,/func \(s \*Service\) loadBalanceHistorySharedPending/);assert.match(native,/s\.analyticsHTMLTransactionService\(\)\.wafPendingPath\(\)/);
 const helper=await read('panel-integration/web/src/loadBalanceTransactions.ts'),manager=await read('panel-integration/web/src/AppModuleManager.vue');assert.match(helper,/loadBalanceReportForSection/);assert.match(helper,/loadBalanceTransactionQueryMatches/);assert.match(manager,/:report="sectionReport\(section\.id\)!"/);assert.match(manager,/const actual=exportableReport\.value/);
 const worker=await read('panel-integration/internal/executor/waf_reload_generation_linux.go');assert.match(worker,/workerSocketReadError/);assert.match(worker,/errors\.Is\(readErr, os\.ErrPermission\)/);
 const old=JSON.parse(await read('dist/apps/load-balance/1.7.1/manifest.json'));assert.equal(old.version,'1.7.1');assert(!old.capabilities.some(s=>s.includes('私有归档')));
 const prior=JSON.parse(await read('dist/apps/load-balance/1.8.0/manifest.json'));assert.equal(prior.version,'1.8.0');assert(prior.capabilities.some(s=>s.includes('私有归档')));assert(!prior.capabilities.some(s=>s.includes('报告不串页')));
 const registry=JSON.parse(await read('registry/apps.json')),contracts=JSON.parse(await read('registry/functional-contracts.json'));assert.equal(registry.apps.find(a=>a.id==='load-balance').version,'1.8.2');assert.equal(contracts.commercial_feature_parity_complete,false);
});
