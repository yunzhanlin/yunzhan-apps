import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {createHash} from 'node:crypto';
const read=p=>readFile(new URL('../'+p,import.meta.url),'utf8');
test('Apache 2.3 private transaction maintenance is exact normal signed ADI source, with a mandatory gate',async()=>{
 const index=JSON.parse(await read('panel-integration/source-sha256.json')),release=JSON.parse(await read('panel-integration/release-source-inputs.json'));
 assert.equal(release.frozen_inputs_sha256,'0c09ccd8603afc68d42caed2a2f1c71672cded67d16e9ab888c9fc6dcc7e0fbb');
 assert.equal(release.archive_sha256,'203eddd7f66a7da29e21c3fce42cf56a7322c53ec519171c864199979d06a68c');
 assert.equal(Object.keys(index.files).length,999);
 for(const file of ['internal/core/apache_waf_history.go','internal/core/apache_waf_history_test.go','internal/executor/apache_waf_history_linux.go','internal/executor/apache_waf_history_linux_test.go','web/src/apacheWafTransactions.ts','web/src/ApacheWafTransactions.vue','scripts/test-apache-waf-transactions.mjs','internal/executor/waf_transaction_linux.go','internal/executor/apache_waf_linux.go','packaging/build-release.sh']){
  const digest=createHash('sha256').update(await read('panel-integration/'+file)).digest('hex');assert.equal(index.files[file],digest,file);assert.equal(release.files[file],digest,file);
 }
 const gates=Object.keys(release.files).filter(f=>/^scripts\/test-[a-z0-9-]+\.mjs$/.test(f));assert.equal(gates.length,23);assert(gates.includes('scripts/test-apache-waf-transactions.mjs'));
 const native=await read('panel-integration/internal/executor/apache_waf_history_linux.go');
 for(const pattern of [/apacheWAFActiveTransactions = 100/,/apacheWAFArchivedTransactions = 512/,/apacheWAFActiveBytes int64 = 128 << 20/,/apacheWAFArchiveBytes int64 = 256 << 20/,/unix\.RENAME_NOREPLACE/,/lockWAFObservation\(\)/,/lockWAFConfiguration\(\)/,/final\.owner != row\.owner/,/final\.inode != row\.inode/,/version != core\.ApacheWAFVersion/])assert.match(native,pattern);
 assert.doesNotMatch(native,/os\.Remove|Config\.Run|wafApplyChange|recoverWAFTransaction\(/);
 const core=await read('panel-integration/internal/core/apache_waf_history.go');assert.match(core,/role != "admin"/);assert.match(core,/apache-waf\.transaction\.archive-requested/);assert.match(core,/apache-waf\.transaction\.archive-confirmed/);assert.match(core,/DecodeApacheWAFHistoryArchive/);
 const ui=await read('panel-integration/web/src/ApacheWafTransactions.vue');assert.match(ui,/apacheTransactionInventory\(out,limit,offset\)/);assert.match(ui,/apacheArchiveReceipt\(out,row\)/);assert.match(ui,/operationError\.value/);assert.match(ui,/不会自动重试/);assert.doesNotMatch(ui,/Blob|createObjectURL/);
});
test('Apache 2.3 release never rewrites earlier packages or calls private fixture success commercial parity',async()=>{
 const registry=JSON.parse(await read('registry/apps.json')),contracts=JSON.parse(await read('registry/functional-contracts.json'));
 const app=registry.apps.find(v=>v.id==='apache-waf'),row=contracts.apps.find(v=>v.id==='apache-waf');
 assert.equal(registry.apps.length,50);assert.equal(app.version,'2.3.0');assert.equal(app.capabilities.length,12);
 assert(app.capabilities.some(v=>v.includes('512 份 / 256 MiB')));assert(app.capabilities.some(v=>v.includes('不删除备份')&&v.includes('旧 config-backups')));
 const old=JSON.parse(await read('dist/apps/apache-waf/2.2.0/manifest.json'));assert.equal(old.version,'2.2.0');assert(!old.capabilities.some(v=>v.includes('512 份')));
 const delivered=JSON.parse(await read('dist/apps/apache-waf/2.3.0/manifest.json'));assert.deepEqual(delivered,app);
 assert.equal(contracts.commercial_feature_parity_complete,false);assert(row.gaps.some(v=>v.includes('完整请求体解析')));assert(row.gaps.some(v=>v.includes('真实已安装签名应用更新')));
 assert(row.scenarios.some(v=>v.includes('12 个 UID501')&&v.includes('不冒充真实 Apache 业务')));assert(row.scenarios.some(v=>v.includes('SIGKILL')&&v.includes('不是断电')));
 assert(row.boundaries.some(v=>v.includes('逻辑预算不是内核硬配额')));assert(row.boundaries.some(v=>v.includes('argv[0]')&&v.includes('原失败保留')));
});
