import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {createRequire} from 'node:module';
import ts from '../web/node_modules/typescript/lib/typescript.js';
const read=p=>readFileSync(new URL('../'+p,import.meta.url),'utf8');
const code=ts.transpileModule(read('web/src/apacheWafTransactions.ts'),{compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.ESNext}}).outputText;
const {apacheTransactionRow,apacheTransactionQuery,apacheTransactionInventory,apacheArchiveBody,apacheArchiveReceipt}=await import('data:text/javascript;base64,'+Buffer.from(code).toString('base64'));
const id='a'.repeat(32),sha='b'.repeat(64);
const row={transaction_id:id,transaction_sha256:sha,transaction_state:'committed',created_at:'2026-10-10T00:00:00Z',transaction_format:2,transaction_files:3,transaction_bytes:1500,transaction_archived:false,transaction_archivable:true};
const inventory={apache_transactions:[row],limit:16,offset:0,total:1,transaction_active_count:1,transaction_archive_count:0,transaction_active_bytes:1500,transaction_archive_bytes:0,transaction_slots_available:99,pending:false,records_retained:true,configuration_changed:false,transaction_archive_ready:true,transaction_replay_ready:true,transaction_archive_blocked:'',scope:'bounded private three-file inventory'};
const vue=createRequire(new URL('../web/package.json',import.meta.url))('vue');
const componentSource=read('web/src/ApacheWafTransactions.vue');
const componentStart=componentSource.indexOf('const limit=16;'),componentEnd=componentSource.indexOf('watch(()=>[props.active');
assert(componentStart>=0&&componentEnd>componentStart);
const actualComponent=ts.transpileModule(componentSource.slice(componentStart,componentEnd),{compilerOptions:{target:ts.ScriptTarget.ES2022}}).outputText;
function componentFixture(version,mode='success') {
 const calls=[];let archived=false;
 const props=vue.reactive({active:true,installed:true,version,parentBusy:false,api:async(path,method,body)=>{
  calls.push({path,method,body:body===undefined?undefined:structuredClone(body)});
  const moved={...row,transaction_archived:true,transaction_archivable:false};
  if(method==='POST') {
   assert.equal(path,'/software/apache-waf/archive-transaction');
   assert.deepEqual(body,{resource_id:id,expected_sha:sha,confirm:'ARCHIVE APACHE TRANSACTION '+id});
   if(mode==='refused')throw Error('owned archive refusal');
   archived=true;
   if(mode==='lost-reply')throw Error('owned reply unavailable');
   return {apache_transactions:[{...moved,transaction_sha256:mode==='foreign-reply'?'c'.repeat(64):sha}],archived:1,replayed:false,records_retained:true,configuration_changed:false,scope:'original private move only'};
  }
  assert.equal(path,'/software/apache-waf/transactions?limit=16&offset=0');
  if(!archived)return structuredClone(inventory);
  return {...structuredClone(inventory),apache_transactions:[moved],transaction_active_count:0,transaction_archive_count:1,transaction_active_bytes:0,transaction_archive_bytes:1500,transaction_slots_available:100};
 }});
 const bindings={props,computed:vue.computed,inventory:vue.ref(),receipt:vue.ref(),selected:vue.ref(),confirm:vue.ref(''),error:vue.ref(''),operationError:vue.ref(''),busy:vue.ref(false),known:vue.ref(false),page:vue.ref(1),apacheArchiveBody,apacheArchiveReceipt,apacheTransactionInventory,apacheTransactionQuery};
 const logic=new Function('bindings','with(bindings){'+actualComponent+';return{readable,writable,selectedCurrent,choose,refresh,archive};}')(bindings);
 return{logic,bindings,calls,props};
}

test('actual component reads native2.4 and admits maintenance only for exact current versions and a verified original selection',async()=>{
 for(const [version,readable,writable]of [['2.0.0',true,false],['2.1.0',true,false],['2.2.0',true,false],['2.3.0',true,true],['2.4.0',true,true],['2.3.1',false,false],['2.4.1',false,false],['v2.4.0',false,false],['2.4.0-beta',false,false]]) {
  const {logic,bindings,calls,props}=componentFixture(version);
  assert.equal(logic.readable.value,readable,version);
  await logic.refresh();assert.equal(calls.length,readable?1:0,version);
  if(readable){logic.choose(bindings.inventory.value.apache_transactions[0]);bindings.confirm.value='ARCHIVE APACHE TRANSACTION '+id;}
  assert.equal(!!logic.writable.value,writable,version);
  if(!writable){await logic.archive();assert.equal(calls.filter(x=>x.method==='POST').length,0,version);continue;}
  props.parentBusy=true;assert.equal(logic.writable.value,false);await logic.archive();assert.equal(calls.length,1);
  props.parentBusy=false;bindings.confirm.value+=' ';assert.equal(logic.writable.value,false);bindings.confirm.value='ARCHIVE APACHE TRANSACTION '+id;
  bindings.known.value=false;assert.equal(logic.writable.value,false);bindings.known.value=true;
  await logic.archive();assert.equal(calls.length,3);assert.equal(calls.filter(x=>x.method==='POST').length,1);assert.equal(bindings.receipt.value.configuration_changed,false);assert.equal(bindings.inventory.value.transaction_archive_count,1);assert.equal(bindings.known.value,true);assert.equal(logic.writable.value,false);
 }
});

test('actual native2.4 archive handler retains unknown outcomes and requires explicit readonly refresh before another write',async()=>{
 for(const version of['2.3.0','2.4.0'])for(const mode of['refused','lost-reply','foreign-reply']) {
  const {logic,bindings,calls}=componentFixture(version,mode);
  await logic.refresh();logic.choose(bindings.inventory.value.apache_transactions[0]);bindings.confirm.value='ARCHIVE APACHE TRANSACTION '+id;assert.equal(logic.writable.value,true);
  await logic.archive();assert.equal(calls.length,2);assert.equal(bindings.receipt.value,undefined);assert.equal(bindings.known.value,false);assert.equal(bindings.busy.value,false);assert.match(bindings.operationError.value,/不会自动重试/);
  await logic.archive();assert.equal(calls.length,2,'unknown outcome silently replayed the archive');
  await logic.refresh();assert.equal(calls.length,3);assert.equal(bindings.known.value,true);assert.equal(bindings.inventory.value.transaction_archive_count,mode==='refused'?0:1);assert.equal(calls.filter(x=>x.method==='POST').length,1);
 }
});
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
