import {test} from 'node:test';import assert from 'node:assert/strict';import {readFileSync} from 'node:fs';
import ts from '../web/node_modules/typescript/lib/typescript.js';
const read=p=>readFileSync(new URL('../'+p,import.meta.url),'utf8');
const compile=async p=>import('data:text/javascript;base64,'+Buffer.from(ts.transpileModule(read(p),{compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.ESNext}}).outputText).toString('base64'));
const {loadBalanceTransactionActions,loadBalanceTransactionFields,loadBalanceTransactionBody}=await compile('web/src/loadBalanceTransactions.ts');
const id='a'.repeat(32),sha='b'.repeat(64),row={transaction_id:id,transaction_sha256:sha,transaction_state:'committed',transaction_archived:false,transaction_archivable:true,transaction_bytes:1000,domain:'private.example.test',changes:['private-backup'],confirm:'old confirmation',health_check:{auto_traffic:true},nodes:[]};
test('selection only copies public original identity and digest with empty confirmation',()=>{
 const fields=loadBalanceTransactionFields(row);assert.deepEqual(fields,{resource_id:id,expected_sha:sha,confirm:''});
 for(const change of [{transaction_id:'../bad'},{transaction_sha256:sha.toUpperCase()},{transaction_state:'unknown'},{transaction_archived:'false'},{transaction_archived:true},{transaction_state:'applying'},{transaction_bytes:0},{transaction_bytes:262145}])assert.equal(loadBalanceTransactionFields({...row,...change}),undefined);
});
test('inventory requests are bounded closed objects even from a populated generic form',()=>{
 assert.deepEqual(loadBalanceTransactionBody('transactions',{...row,limit:16,offset:0}),{limit:16,offset:0});
 assert.deepEqual(loadBalanceTransactionBody('transactions',{}),{limit:16,offset:0});
 for(const change of [{limit:0},{limit:33},{limit:'16'},{offset:-1},{offset:2561},{offset:1.2}])assert.throws(()=>loadBalanceTransactionBody('transactions',change));
});
test('archive is exact original ID/digest/confirmation, never routing or filesystem input',()=>{
 const form={...row,resource_id:id,expected_sha:sha,confirm:'ARCHIVE LOAD TRANSACTION '+id};
 assert.deepEqual(loadBalanceTransactionBody('archive-transaction',form),{resource_id:id,expected_sha:sha,confirm:form.confirm});
 for(const change of [{confirm:''},{confirm:form.confirm+' '},{resource_id:'c'.repeat(32)},{expected_sha:sha.toUpperCase()}])assert.throws(()=>loadBalanceTransactionBody('archive-transaction',{...form,...change}));
 assert.throws(()=>loadBalanceTransactionBody('remove',form));assert.deepEqual(loadBalanceTransactionActions,['transactions','archive-transaction']);
});
test('normal packaging, both server routes and manager require the dedicated closed handlers',()=>{
 assert.match(read('packaging/build-release.sh'),/test-load-balance-transactions\.mjs/);
 for(const p of ['internal/core/app_modules.go','internal/executor/app_modules_linux.go'])assert.match(read(p),/DecodeLoadBalanceHistoryInput/);
 const manager=read('web/src/AppModuleManager.vue');assert.match(manager,/loadBalanceTransactionBody\(action,form\.value\)/);assert.match(manager,/activeTab\.value="transaction-archive"/);assert.match(manager,/事务清单|事务标识|事务记录身份/);
 const native=read('internal/executor/app_load_balance_history_linux.go');assert.match(native,/unix\.RENAME_NOREPLACE/);assert.doesNotMatch(native,/os\.Remove|Config\.Run|reloadLoadBalance|wafApplyChange/);assert.match(read('internal/executor/app_load_balance_linux.go'),/loadBalanceArchivedIDReserved\(tx\.ID\)/);
 assert.match(read('internal/core/app_module_workspace.go'),/配置事务库存/);assert.match(read('web/src/AppModuleReport.vue'),/完整事务文件 SHA-256/);
});
