import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {createHash} from 'node:crypto';
const read=p=>readFile(new URL('../'+p,import.meta.url),'utf8');
test('1.8.2 report snapshots are exported from exact current normal signed ABH inputs and mandatory gate',async()=>{
 const index=JSON.parse(await read('panel-integration/source-sha256.json')),release=JSON.parse(await read('panel-integration/release-source-inputs.json'));
 assert.equal(release.frozen_inputs_sha256,'85c54234bfa58b6e25b8919f96bab560466ba197493e233b11cef206d75971fe');
 assert.equal(release.archive_sha256,'e08523947e4c913d470aa784e79c556796ca7df958de5f07cc75fc667f50b243');
 assert.equal(Object.keys(index.files).length,998);
 for(const file of ['internal/core/load_balance_report_export.go','internal/core/load_balance_report_export_test.go','web/src/loadBalanceReportExport.ts','scripts/test-load-balance-report-export.mjs','internal/core/app_modules.go','web/src/AppModuleManager.vue','packaging/build-release.sh']){
  const digest=createHash('sha256').update(await read('panel-integration/'+file)).digest('hex');assert.equal(index.files[file],digest,file);assert.equal(release.files[file],digest,file);
 }
 const gates=Object.keys(release.files).filter(f=>/^scripts\/test-[a-z0-9-]+\.mjs$/.test(f));assert.equal(gates.length,23);assert(gates.includes('scripts/test-load-balance-report-export.mjs'));
 const native=await read('panel-integration/internal/core/load_balance_report_export.go');
 for(const pattern of [/loadBalanceExportMaxBody\s*= 1 << 20/,/loadBalanceExportMaxBytes\s*= 8 << 20/,/loadBalanceExportMaxTickets = 32/,/loadBalanceExportPerSession = 8/,/loadBalanceExportTTL\s*= 5 \* time.Minute/,/decoder.UseNumber\(\)/,/Owner != loadBalanceExportOwner\(u\)/,/a.authorize\(/,/len\(query\["sha256"\]\) != 1/,/Cache-Control", "no-store, private"/])assert.match(native,pattern);
 assert.doesNotMatch(native,/a\.Executor|os\.ReadFile|os\.WriteFile|exec\.Command/);
 const manager=await read('panel-integration/web/src/AppModuleManager.vue');assert(manager.includes('tag="a"'),'real attachment anchor');assert(manager.includes(':href="busy ? undefined : nativeReportExportHref"'),'busy state must suppress attachment navigation');
 const helper=await read('panel-integration/web/src/loadBalanceReportExport.ts');assert.match(helper,/sections\[section\]\?\.includes\(receipt.action\)/);assert.match(helper,/expires<=now/);assert.match(helper,/\/api\/app-modules\/load-balance\/report-export/);
});
test('1.8.2 publishes bounded nonsecret snapshots without rewriting old packages or declaring all apps complete',async()=>{
 const registry=JSON.parse(await read('registry/apps.json')),contracts=JSON.parse(await read('registry/functional-contracts.json'));
 const app=registry.apps.find(a=>a.id==='load-balance'),row=contracts.apps.find(a=>a.id===app.id);
 assert.equal(registry.apps.length,50);assert.equal(app.version,'1.8.2');assert(app.capabilities.some(s=>s.includes('5 分钟')&&s.includes('不导出凭据')));
 const prior=JSON.parse(await read('dist/apps/load-balance/1.8.1/manifest.json'));assert.equal(prior.version,'1.8.1');assert(!prior.capabilities.some(s=>s.includes('5 分钟')));
 const delivered=JSON.parse(await read('dist/apps/load-balance/1.8.2/manifest.json'));assert.deepEqual(delivered,app);
 assert.equal(contracts.commercial_feature_parity_complete,false);assert(row.gaps.some(s=>s.includes('TCP/UDP')));assert(row.gaps.some(s=>s.includes('其他实际浏览器')));
 assert(row.scenarios.some(s=>s.includes('两次直接点击')&&s.includes('7781')));assert(row.scenarios.some(s=>s.includes('旧快照 410')&&s.includes('1:3')));
 assert(row.boundaries.some(s=>s.includes('最多 32 份 / 8 MiB / 5 分钟')));assert(row.boundaries.some(s=>s.includes('下载事件超时')));
});
