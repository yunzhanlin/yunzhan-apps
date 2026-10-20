import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import ts from '../web/node_modules/typescript/lib/typescript.js';
const read=p=>readFileSync(new URL('../'+p,import.meta.url),'utf8');
const code=ts.transpileModule(read('web/src/apacheWafTransactions.ts'),{compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.ESNext}}).outputText;
const {apacheTransactionRow,apacheTransactionQuery,apacheTransactionInventory,apacheArchiveBody,apacheArchiveReceipt}=await import('data:text/javascript;base64,'+Buffer.from(code).toString('base64'));
const id='a'.repeat(32),sha='b'.repeat(64);
const row={transaction_id:id,transaction_sha256:sha,transaction_state:'committed',created_at:'2026-10-10T00:00:00Z',transaction_format:2,transaction_files:3,transaction_bytes:1500,transaction_archived:false,transaction_archivable:true};
const inventory={apache_transactions:[row],limit:16,offset:0,total:1,transaction_active_count:1,transaction_archive_count:0,transaction_active_bytes:1500,transaction_archive_bytes:0,transaction_slots_available:99,pending:false,records_retained:true,configuration_changed:false,transaction_archive_ready:true,transaction_replay_ready:true,transaction_archive_blocked:'',scope:'bounded private three-file inventory'};
test('closed selection and bodies cannot inherit backup contents or web configuration',()=>{
 assert.equal(apacheTransactionRow(row),true);
 const polluted={...row,changes:[{old_data:'secret'}],nodes:[{ip:'127.0.0.1'}],resource_id:'old'};
 assert.deepEqual(apacheArchiveBody(polluted,'ARCHIVE APACHE TRANSACTION '+id),{resource_id:id,expected_sha:sha,confirm:'ARCHIVE APACHE TRANSACTION '+id});
 for(const change of [{transaction_id:'../bad'},{transaction_sha256:sha.toUpperCase()},{transaction_state:'unknown'},{transaction_format:1},{transaction_files:2},{transaction_bytes:0},{transaction_bytes:16777217},{created_at:'bad'},{transaction_archived:'false'},{transaction_archived:true},{transaction_state:'applying'}])assert.throws(()=>apacheArchiveBody({...row,...change},'ARCHIVE APACHE TRANSACTION '+id));
 for(const confirm of ['', 'ARCHIVE LOAD TRANSACTION '+id,'ARCHIVE APACHE TRANSACTION '+id+' '])assert.throws(()=>apacheArchiveBody(row,confirm));
 assert.deepEqual(apacheArchiveBody({...row,transaction_archived:true,transaction_archivable:false},'ARCHIVE APACHE TRANSACTION '+id),{resource_id:id,expected_sha:sha,confirm:'ARCHIVE APACHE TRANSACTION '+id});
});
test('inventory pagination exact identity and complete counters never return partial statistics',()=>{
 assert.equal(apacheTransactionQuery(),'?limit=16&offset=0');assert.equal(apacheTransactionQuery(32,612),'?limit=32&offset=612');
 for(const [limit,offset] of [[0,0],[33,0],['16',0],[16,-1],[16,613],[16,0.5]])assert.throws(()=>apacheTransactionQuery(limit,offset));
 assert.equal(apacheTransactionInventory(inventory,16,0),true);
 for(const change of [{total:2},{transaction_active_count:101},{transaction_archive_count:513},{transaction_active_bytes:134217729},{transaction_archive_bytes:268435457},{transaction_slots_available:100},{limit:32},{offset:1},{pending:true},{transaction_replay_ready:false},{records_retained:false},{configuration_changed:true},{apache_transactions:[row,row]}])assert.equal(apacheTransactionInventory({...inventory,...change},16,0),false);
 assert.equal(apacheTransactionInventory(inventory,32,0),false);assert.equal(apacheTransactionInventory(inventory,16,16),false);
 const pending={...inventory,pending:true,transaction_archive_ready:false,transaction_replay_ready:false,apache_transactions:[{...row,transaction_archivable:false}]};
 assert.equal(apacheTransactionInventory(pending,16,0),true);
});
test('only exact original moved or replayed private record is a receipt, never a cached inventory',()=>{
 const archived={...row,transaction_archived:true,transaction_archivable:false};
 const receipt={apache_transactions:[archived],archived:1,replayed:false,records_retained:true,configuration_changed:false,scope:'no configuration change'};
 assert.equal(apacheArchiveReceipt(receipt,row),true);assert.equal(apacheArchiveReceipt(inventory,row),false);
 for(const change of [{archived:2},{replayed:true},{replayed:'false'},{configuration_changed:true},{records_retained:false},{apache_transactions:[row]},{apache_transactions:[{...archived,transaction_sha256:'c'.repeat(64)}]},{apache_transactions:[{...archived,transaction_bytes:1501}]},{apache_transactions:[{...archived,created_at:'2026-10-09T00:00:00Z'}]}])assert.equal(apacheArchiveReceipt({...receipt,...change},row),false);
 assert.equal(apacheArchiveReceipt({...receipt,replayed:true},archived),true);
});
test('normal packaging and native dedicated lock/closed parser/immutable archive gates are mandatory',()=>{
 assert.match(read('packaging/build-release.sh'),/test-apache-waf-transactions\.mjs/);
 for(const path of ['internal/core/apache_waf.go','internal/executor/apache_waf_linux.go'])assert.match(read(path),/apacheWAFHistoryRoutes\(m\)/);
 for(const path of ['internal/core/apache_waf_history.go','internal/executor/apache_waf_history_linux.go'])assert.match(read(path),/DecodeApacheWAFHistoryArchive/);
 const native=read('internal/executor/apache_waf_history_linux.go');assert.match(native,/unix\.RENAME_NOREPLACE/);assert.match(native,/lockWAFObservation/);assert.match(native,/lockWAFConfiguration/);assert.doesNotMatch(native,/os\.Remove|Config\.Run|wafApplyChange|recoverWAFTransaction\(/);
 assert.match(read('internal/executor/waf_transaction_linux.go'),/apacheWAFReserveTransaction\(context\.Background\(\), tx\)/);
 const workspace=read('web/src/WafWorkspace.vue');assert.match(workspace,/<ApacheWafTransactions/);
 const component=read('web/src/ApacheWafTransactions.vue');assert.match(component,/apacheTransactionInventory\(out,limit,offset\)/);assert.match(component,/apacheArchiveReceipt\(out,row\)/);assert.match(component,/ticket!==epoch/);assert.match(component,/operationError\.value/);assert.match(component,/不会自动重试/);assert.match(component,/ticket===epoch&&receipt\.value\)await refresh\(\)/);assert.doesNotMatch(component,/Blob|createObjectURL|setInterval/);
 const apply=read('internal/executor/apache_waf_linux.go');assert.doesNotMatch(apply,/os\.MkdirAll\(base, 0700\)/);assert.match(apply,/Keep old config-backups untouched/);
});
