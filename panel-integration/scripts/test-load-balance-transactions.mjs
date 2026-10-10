import {test} from 'node:test';import assert from 'node:assert/strict';import {readFileSync} from 'node:fs';
import ts from '../web/node_modules/typescript/lib/typescript.js';
const read=p=>readFileSync(new URL('../'+p,import.meta.url),'utf8');
const compile=async p=>import('data:text/javascript;base64,'+Buffer.from(ts.transpileModule(read(p),{compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.ESNext}}).outputText).toString('base64'));
const {loadBalanceTransactionActions,loadBalanceTransactionFields,loadBalanceTransactionBody,loadBalanceReportForSection,loadBalanceTransactionQueryMatches}=await compile('web/src/loadBalanceTransactions.ts');
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
test('cached entry, inventory and archive reports never impersonate another workspace receipt',()=>{
 const entries={entries:[{domain:'actual.example.test',revision:5}],http_health:[]};
 const inventory={load_transactions:[row],records_retained:true,configuration_changed:false,limit:16,offset:0,total:1,transaction_active_count:1,transaction_archive_count:0};
 const archived={...row,transaction_archived:true,transaction_archivable:false};
 const receipt={load_transactions:[archived],archived:1,replayed:false,records_retained:true,configuration_changed:false};
 assert.equal(loadBalanceReportForSection('entries',entries),entries);
 assert.equal(loadBalanceReportForSection('transactions',entries),undefined);assert.equal(loadBalanceReportForSection('transaction-archive',entries),undefined);
 assert.equal(loadBalanceReportForSection('transactions',inventory),inventory);assert.equal(loadBalanceReportForSection('transaction-archive',inventory),undefined);
 assert.equal(loadBalanceReportForSection('transaction-archive',receipt),receipt);assert.equal(loadBalanceReportForSection('transactions',receipt),undefined);
 for(const section of ['entries','entry','health','recovery'])for(const value of [inventory,receipt])assert.equal(loadBalanceReportForSection(section,value),undefined);
 for(const section of ['overview','version','history','unrecognized'])assert.equal(loadBalanceReportForSection(section,entries),undefined);
 assert.equal(loadBalanceReportForSection('reports',inventory),inventory);assert.equal(loadBalanceReportForSection('reports',receipt),receipt);
 for(const value of [undefined,[],{...inventory,total:2},{...inventory,limit:0},{...inventory,transaction_active_count:513},{...inventory,load_transactions:[{...row,transaction_sha256:'wrong'}]},{...inventory,records_retained:false},{...inventory,configuration_changed:true}])assert.equal(loadBalanceReportForSection('transactions',value),undefined);
 for(const change of [{replayed:'false'},{archived:2},{load_transactions:[row]},{load_transactions:[]},{records_retained:false}])assert.equal(loadBalanceReportForSection('transaction-archive',{...receipt,...change}),undefined);
 assert.equal(loadBalanceTransactionQueryMatches(inventory,{limit:16,offset:0}),true);assert.equal(loadBalanceTransactionQueryMatches(inventory,{}),true);
 for(const form of [{limit:32,offset:0},{limit:16,offset:16},{limit:'16',offset:0}])assert.equal(loadBalanceTransactionQueryMatches(inventory,form),false);
 const manager=read('web/src/AppModuleManager.vue');assert.match(manager,/loadBalanceReportForSection\(section,report\.value\)/);assert.match(manager,/:report="sectionReport\(section\.id\)!"/);assert.match(manager,/const actual=exportableReport\.value/);assert.match(manager,/其他页面的缓存结果不会当作本页回执/);
});
test('normal packaging, both server routes and manager require the dedicated closed handlers',()=>{
 assert.match(read('packaging/build-release.sh'),/test-load-balance-transactions\.mjs/);
 for(const p of ['internal/core/app_modules.go','internal/executor/app_modules_linux.go'])assert.match(read(p),/DecodeLoadBalanceHistoryInput/);
 const manager=read('web/src/AppModuleManager.vue');assert.match(manager,/loadBalanceTransactionBody\(action,form\.value\)/);assert.match(manager,/activeTab\.value="transaction-archive"/);assert.match(manager,/事务清单|事务标识|事务记录身份/);
 const native=read('internal/executor/app_load_balance_history_linux.go');assert.match(native,/unix\.RENAME_NOREPLACE/);assert.doesNotMatch(native,/os\.Remove|Config\.Run|reloadLoadBalance|wafApplyChange/);assert.match(read('internal/executor/app_load_balance_linux.go'),/loadBalanceArchivedIDReserved\(tx\.ID\)/);
 assert.match(read('internal/core/app_module_workspace.go'),/配置事务库存/);assert.match(read('web/src/AppModuleReport.vue'),/完整事务文件 SHA-256/);
});
