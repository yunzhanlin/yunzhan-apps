import {test} from 'node:test';
import assert from 'node:assert/strict';
import {beforeApacheBuildDependencyAdmission} from './release-build-baseline.mjs';
import {createHash} from 'node:crypto';
import {readFileSync} from 'node:fs';
import {createRequire} from 'node:module';
import ts from '../web/node_modules/typescript/lib/typescript.js';
import * as guards from '../web/src/apacheCCArchives.ts';
import {browserSHA256} from '../web/src/browserSHA256.ts';
const vue=createRequire(new URL('../web/package.json',import.meta.url))('vue');
const actor='a'.repeat(32),otherActor='b'.repeat(32),empty=browserSHA256('');
const content=()=>{const data=new Uint8Array(262147);data.fill(120);data[data.length-1]=10;return data;};
function entry(request={request_id:'c'.repeat(32),expected_revision:7,allow_incomplete:false},data=content(),rootGroup=0){
 const source={device:'2049',inode:'18446744073709551610',uid:33,gid:33,bytes:data.length,sha256:browserSHA256(data)};
 const archive={...source,inode:'18446744073709551608',uid:0,gid:rootGroup};
 return {id:request.request_id,state:'completed',source_status:'matches-witness',record_sha256:{intent:'d'.repeat(64),prepared:'e'.repeat(64),completed:'f'.repeat(64)},intent:{format:2,id:request.request_id,at:'2026-11-03T14:00:00Z',request:structuredClone(request),source,tail_incomplete:false},prepared:{format:2,id:request.request_id,fresh:{...source,inode:'18446744073709551609',bytes:0,sha256:empty},archive},completed:{format:2,id:request.request_id,at:'2026-11-03T14:00:01Z',archive}};
}
const fixture=(rows=[])=>({archives:structuredClone(rows),history:[],max_history:32,current:{available:true,bytes:128,max_bytes:33554432,tail_incomplete:false,capacity_near_limit:false,read_only:true},inventory_complete:true,maintenance_healthy:rows.every(x=>x.state!=='unknown'),max_archives:8,max_archive_bytes:33554432,read_only:true,atomic_name_exchange:true,reloads_apache:false});
const closed=(request,confirmed=false)=>({kind:'closed',record:{format:1,state:'closed-before-archive',at:'2026-11-03T14:00:02Z',request:structuredClone(request)},sha256:'1'.repeat(64),...(confirmed?{late_dispatch_refused:true,current_log_untouched:true}:{read_only:true})});
const source=readFileSync(new URL('../web/src/ApacheCCArchives.vue',import.meta.url),'utf8');
const body=source.slice(source.indexOf('const inventory=ref'),source.indexOf('</script>'));
const actual=ts.transpileModule(body,{compilerOptions:{target:ts.ScriptTarget.ES2022}}).outputText;
const settle=async()=>{await vue.nextTick();await new Promise(setImmediate);};
function component({api,storage=new Map(),props:overrides={},confirm=async()=>{},storageFailure=false}={}){
 const calls=[],downloaded=[],cleanups=[];let nonce=1;
 const props=vue.reactive({active:false,installed:true,version:'2.5.1',implementation:'2.5.1',actor,revision:7,parentBusy:false,...overrides,api:async(...args)=>{calls.push(args.map(v=>v!==null&&typeof v==="object"?JSON.parse(JSON.stringify(v)):v));return api(...args);}});
 const sessionStorage={getItem(key){if(storageFailure)throw Error('owned storage denial');return storage.get(key)??null;},setItem(key,value){if(storageFailure)throw Error('owned storage denial');storage.set(key,value);},removeItem(key){if(storageFailure)throw Error('owned storage denial');storage.delete(key);}};
 let blob;
 const bindings={...guards,props,computed:vue.computed,ref:vue.ref,watch:vue.watch,onBeforeUnmount:fn=>cleanups.push(fn),ElMessageBox:{confirm},sessionStorage,browserSHA256,randomId:()=>String(nonce++).padStart(32,'0'),formatPanelDateTime:v=>v,URL:{createObjectURL(value){blob=value;return 'blob:owned-fixture';},revokeObjectURL(){}},document:{createElement(){return {click(){downloaded.push(blob);}}}}};
 const scope=vue.effectScope();const logic=scope.run(()=>new Function('bindings','with(bindings){'+actual+';return{inventory,known,error,operationError,storageError,storageReady,reading,writing,confirming,supported,pending,observation,allowIncomplete,canArchive,canClose,archive,refresh,closeUnstarted,download,receipt,recovery,pendingRetention,pendingHistory,inspectRecovery,retainUnknown,acknowledgeRetainedOriginal,preserveHistory,acknowledgeObservedRetention,priorRetentions};}')(bindings));
 return {props,calls,logic,storage,downloaded,stop(){cleanups.forEach(f=>f());scope.stop();}};
}

test('CC archive identities retain64-bit decimals and reject false completion or missing current state',()=>{
 const row=entry();assert.equal(guards.ccArchiveEntry(row),true);assert.equal(guards.ccArchiveInventory(fixture([row])),true);
 for(const change of [{source:{...row.intent.source,inode:18446744073709551610}},{source:{...row.intent.source,uid:0}},{request:{...row.intent.request,request_id:'9'.repeat(32)}}])assert.equal(guards.ccArchiveEntry({...row,intent:{...row.intent,...change}}),false);
 for(const patch of [{inventory_complete:false},{max_archives:9},{reloading:true},{current:undefined},{current:{...fixture().current,available:false}},{current:{...fixture().current,capacity_near_limit:true}},{archives:[row,row]}])assert.equal(guards.ccArchiveInventory({...fixture([row]),...patch}),false,JSON.stringify(patch));
 const pending={id:row.id,state:'unknown',record_sha256:{},problem:'original partial intent'};assert.equal(guards.ccArchiveInventory(fixture([pending])),true);assert.equal(guards.ccArchiveInventory({...fixture([pending]),maintenance_healthy:true}),false);
});

test('actual CC archive component needs exact installed251, original account and current nonempty log',async()=>{
 for(const patch of [{version:'2.5.0',implementation:'2.5.0'},{implementation:'2.5.0'},{installed:false},{actor:''},{version:'2.5.1-alias',implementation:'2.5.1-alias'}]){
  const t=component({api:async()=>fixture(),props:{active:true,...patch}});try{await settle();await t.logic.archive();assert.equal(t.calls.length,0);}finally{t.stop();}
 }
 const t=component({api:async()=>fixture()});try{t.props.active=true;await settle();assert.equal(t.logic.canArchive.value,true);t.props.parentBusy=true;assert.equal(t.logic.canArchive.value,false);t.props.parentBusy=false;t.logic.inventory.value.current.bytes=0;assert.equal(t.logic.canArchive.value,false);t.logic.inventory.value.current.bytes=1;t.logic.inventory.value.current.tail_incomplete=true;assert.equal(t.logic.canArchive.value,false);t.logic.allowIncomplete.value=true;assert.equal(t.logic.canArchive.value,true);}finally{t.stop();}
});

test('actual double click saves the original nonce before one archive POST and never refills policy',async()=>{
 let accept;const confirmation=new Promise(resolve=>accept=resolve),storage=new Map();let rows=[];
 const t=component({storage,confirm:()=>confirmation,api:async(path,method,request)=>{if(method==='POST'){assert.ok(storage.has('yunzhan.apache-cc-archive.v1.'+actor));assert.equal(path,'/software/apache-waf/cc-log/archive');assert.deepEqual(request,{request_id:'0'.repeat(31)+'1',expected_revision:7,allow_incomplete:false});const row=entry(request);rows=[row];return row;}return fixture(rows);}});
 try{t.props.active=true;await settle();const first=t.logic.archive();await t.logic.archive();assert.equal(t.logic.confirming.value,true);accept();await first;assert.equal(t.calls.filter(v=>v[1]==='POST').length,1);assert.equal(storage.size,0);assert.equal(t.logic.pending.value,undefined);assert.equal(t.props.revision,7);assert.equal(t.logic.inventory.value.archives.length,1);}finally{t.stop();}
});

test('lost archive reply persists across remount and cannot be automatically retried or closed after starting',async()=>{
 const storage=new Map();let original,row;
 const api=async(path,method,request)=>{if(method==='POST'){original=structuredClone(request);row={id:request.request_id,state:'unknown',record_sha256:{},problem:'original phase interrupted'};throw Error('owned lost reply');}if(path.includes('/requests/'))return {kind:'archive',record:row,read_only:true};return fixture(row?[row]:[]);};
 let t=component({api,storage});try{t.props.active=true;await settle();await t.logic.archive();assert.equal(t.logic.pending.value.request_id,original.request_id);assert.equal(t.logic.canClose.value,false);assert.match(t.logic.operationError.value,/不会自动重发/);await t.logic.archive();assert.equal(t.calls.filter(x=>x[1]==='POST').length,1);}finally{t.stop();}
 t=component({api,storage,props:{active:true}});try{await settle();assert.deepEqual(vue.toRaw(t.logic.pending.value),original);assert.equal(t.calls.filter(x=>x[1]==='POST').length,0);assert.equal(t.logic.canArchive.value,false);assert.equal(t.logic.canClose.value,false);assert.equal(storage.size,1);}finally{t.stop();}
});

test('a proven unstarted original is closed explicitly and a lost closure reply requires its own receipt',async()=>{
 let original,isClosed=false,closeCalls=0;
 const t=component({api:async(path,method,request)=>{
  if(method==='POST'&&path.endsWith('/archive')){original=structuredClone(request);throw Error('original transport failure');}
  if(method==='POST'){closeCalls++;isClosed=true;if(closeCalls===1)throw Error('closure reply lost');return closed(original,true);}
  if(path.includes('/requests/'))return isClosed?closed(original):{kind:'not-recorded',request_id:original.request_id,read_only:true,automatic_retry_allowed:false};
  return fixture();
 }});
 try{t.props.active=true;await settle();await t.logic.archive();assert.equal(t.logic.canClose.value,true);assert.equal(closeCalls,0);await t.logic.closeUnstarted();assert.equal(closeCalls,1);assert.ok(t.logic.pending.value);assert.equal(t.logic.observation.value.kind,'closed');assert.equal(t.logic.canArchive.value,false);await t.logic.closeUnstarted();assert.equal(closeCalls,2);assert.equal(t.logic.pending.value,undefined);assert.equal(t.calls.filter(x=>x[0].endsWith('/archive')&&x[1]==='POST').length,1);}finally{t.stop();}
});

test('storage denial or a malformed original ticket never sends a mutation and remains visible after refresh',async()=>{
 for(const options of [{storageFailure:true},{storage:new Map([['yunzhan.apache-cc-archive.v1.'+actor,'{"broken":true}']])}]){
  const t=component({...options,api:async()=>fixture(),props:{active:true}});try{await settle();assert.equal(t.logic.known.value,true);assert.equal(t.logic.storageReady.value,false);assert.ok(t.logic.storageError.value);await t.logic.archive();assert.equal(t.calls.filter(x=>x[1]==='POST').length,0);}finally{t.stop();}
 }
});

test('late prior account mutation reply cannot clear a new account original request or UI read',async()=>{
 let finish;
 const t=component({api:async(path,method)=>method==='POST'?new Promise(resolve=>finish=resolve):fixture()});
 try{t.props.active=true;await settle();const old=t.logic.archive();await settle();assert.equal(t.logic.writing.value,true);const original=JSON.parse(t.storage.get('yunzhan.apache-cc-archive.v1.'+actor));t.props.actor=otherActor;await settle();assert.equal(t.logic.pending.value,undefined);finish(entry(original));await old;assert.equal(t.props.actor,otherActor);assert.equal(t.logic.receipt.value,'');assert.equal(t.storage.has('yunzhan.apache-cc-archive.v1.'+actor),true);assert.equal(t.logic.known.value,true);}finally{t.stop();}
});

test('download validates all bounded chunks and full SHA before producing exactly the original private bytes',async()=>{
 const data=content(),row=entry(undefined,data);
 const t=component({api:async(path)=>{
  if(path.endsWith('/archives'))return fixture([row]);if(path.endsWith('/'+row.id))return row;
  const part=Number(path.split('/').at(-1)),chunk=data.slice(part*262144,(part+1)*262144);
  return {archive_id:row.id,part,offset:part*262144,bytes:chunk.length,total_bytes:data.length,sha256:row.completed.archive.sha256,data_base64:Buffer.from(chunk).toString('base64'),raw_original_private_log:true,tail_incomplete:false,original_outcome_unknown:false};
 }});
 try{t.props.active=true;await settle();await t.logic.download(row);assert.equal(t.downloaded.length,1);assert.deepEqual(new Uint8Array(await t.downloaded[0].arrayBuffer()),data);assert.equal(t.calls.filter(x=>x[1]==='POST').length,0);assert.equal(t.calls.filter(x=>x[0].includes('/chunks/')).length,2);}finally{t.stop();}
});

test('a corrupt complete-length chunk or foreign receipt never becomes a partial downloaded file',async()=>{
 for(const mode of ['corrupt-bytes','foreign-identity']){
  const data=content(),row=entry(undefined,data);const t=component({api:async(path)=>{
   if(path.endsWith('/archives'))return fixture([row]);if(path.endsWith('/'+row.id))return row;
   const part=Number(path.split('/').at(-1)),chunk=data.slice(part*262144,(part+1)*262144);if(mode==='corrupt-bytes'&&part===1)chunk[0]^=1;
   return {archive_id:mode==='foreign-identity'?'0'.repeat(32):row.id,part,offset:part*262144,bytes:chunk.length,total_bytes:data.length,sha256:row.completed.archive.sha256,data_base64:Buffer.from(chunk).toString('base64'),raw_original_private_log:true,tail_incomplete:false,original_outcome_unknown:false};
  }});try{t.props.active=true;await settle();await t.logic.download(row);assert.equal(t.downloaded.length,0);assert.ok(t.logic.error.value);assert.equal(t.calls.filter(x=>x[1]==='POST').length,0);}finally{t.stop();}
 }
});

function unknownRow(request={request_id:'c'.repeat(32),expected_revision:7,allow_incomplete:false}){return {id:request.request_id,state:'unknown',record_sha256:{},problem:'original unknown phase'};}
function recoveryFixture(row=unknownRow(),data=content(),prior=false,rootGroup=0){
 const base=entry({request_id:row.id,expected_revision:7,allow_incomplete:false},data,rootGroup),meta={device:'2049',inode:'18446744073709551500',uid:0,gid:rootGroup,bytes:17,sha256:'a'.repeat(64)};
 const snapshot={format:2,source_identity_only:true,id:row.id,files:{'intent.json':meta,'data.log':base.prepared.archive,...(prior?{['retain-intent-'+ '4'.repeat(32)+'.json']:{...meta,inode:'18446744073709551501',bytes:0,sha256:empty}}:{})}};
 return {record:row,snapshot,snapshot_sha256:guards.ccSnapshotSHA(snapshot),read_only:true,automatic_replay_allowed:false};
}
function retainedRow(proof=recoveryFixture(),retainerGroup=0){
 const base=entry({request_id:proof.record.id,expected_revision:7,allow_incomplete:false}),data=proof.snapshot.files['data.log'];
 return {id:proof.record.id,state:'retained-unknown',record_sha256:{retained:'d'.repeat(64)},problem:'original result remains unknown',retained:{format:2,id:proof.record.id,receipt_id:'5'.repeat(32),at:'2026-11-03T14:01:00Z',outcome:'unknown-retained',snapshot:structuredClone(proof.snapshot),snapshot_sha256:proof.snapshot_sha256,retention_intent:{device:'2049',inode:'18446744073709551502',uid:0,gid:retainerGroup,bytes:500,sha256:'6'.repeat(64)},...(data?{archive:{...data}}:{}),original_current_log:base.prepared.fresh,no_replay:true,no_name_exchange:true,current_log_untouched:true,original_outcome_unknown:true}};
}
function historyFixture(row=entry(),history=false){const recovery=recoveryFixture(unknownRow({request_id:row.id,expected_revision:7,allow_incomplete:false}));return {record:row,snapshot:recovery.snapshot,snapshot_sha256:recovery.snapshot_sha256,history,read_only:true,no_delete:true};}

test('retained unknown evidence has an independent canonical snapshot digest and never pretends to be completed',()=>{
 const proof=recoveryFixture(),row=retainedRow(proof);
 const x=proof.snapshot.files['data.log'],y=proof.snapshot.files['intent.json'];
 const expected=JSON.stringify({format:2,id:proof.record.id,files:{'data.log':x,'intent.json':y},source_identity_only:true});
 assert.equal(proof.snapshot_sha256,createHash('sha256').update(expected).digest('hex'));
 const reordered={...proof,snapshot:{files:Object.fromEntries(Object.entries(proof.snapshot.files).reverse()),id:proof.record.id,format:2,source_identity_only:true}};
 assert.equal(guards.ccRecovery(reordered,row.id),true);assert.equal(guards.ccArchiveEntry(row),true);assert.equal(guards.ccArchiveInventory(fixture([row])),true);
 for(const bad of [{...row,state:'completed'},{...row,retained:{...row.retained,original_outcome_unknown:false}},{...row,retained:{...row.retained,archive:{...row.retained.archive,inode:'2'}}},{...row,retained:{...row.retained,snapshot_sha256:'f'.repeat(64)}}])assert.equal(guards.ccArchiveEntry(bad),false);
 assert.equal(guards.ccRecovery({...proof,snapshot_sha256:'0'.repeat(64)},row.id),false);
 const emptyProof={...proof,snapshot:{format:2,id:row.id,files:{},source_identity_only:true}};emptyProof.snapshot_sha256=guards.ccSnapshotSHA(emptyProof.snapshot);
 const noData=retainedRow(emptyProof);assert.equal(guards.ccArchiveEntry(noData),true);assert.equal(guards.ccArchiveData(noData),undefined);
 const historical=fixture();historical.history=[row];assert.equal(guards.ccArchiveInventory(historical),true);historical.archives=[row];assert.equal(guards.ccArchiveInventory(historical),false);
});

test('lost retention reply is only observed and the original unknown archive needs an explicit acknowledgement',async()=>{
 const request={request_id:'c'.repeat(32),expected_revision:7,allow_incomplete:false},storage=new Map([['yunzhan.apache-cc-archive.v1.'+actor,JSON.stringify(request)]]);
 let row=unknownRow(request),proof=recoveryFixture(row),posted=0;
 const api=async(path,method,body)=>{
  if(method==='POST'){posted++;assert.ok(storage.has('yunzhan.apache-cc-archive.v1.'+actor+'.retain'));assert.deepEqual(body,{sha256:proof.snapshot_sha256,confirm_unknown:true});row=retainedRow(proof);throw Error('owned lost retention reply');}
  if(path.endsWith('/recovery'))return {...proof,record:row};if(path.includes('/requests/'))return {kind:'archive',record:row,read_only:true};return fixture([row]);
 };
 let t=component({api,storage,props:{active:true}});
 try{await settle();await t.logic.inspectRecovery(row);await t.logic.retainUnknown();assert.equal(posted,1);assert.equal(t.logic.pendingRetention.value,undefined);assert.ok(t.logic.pending.value);assert.equal(t.logic.canArchive.value,false);assert.match(t.logic.receipt.value,/原归档结果仍未知/);}finally{t.stop();}
 t=component({api,storage,props:{active:true}});
 try{await settle();assert.equal(posted,1);assert.equal(t.logic.pending.value.request_id,request.request_id);await t.logic.acknowledgeRetainedOriginal();assert.equal(posted,1);assert.equal(t.logic.pending.value,undefined);assert.equal(t.logic.canArchive.value,true);assert.match(t.logic.receipt.value,/原结果未知/);}finally{t.stop();}
});

test('interrupted retention adopts a fresh snapshot only after an explicit click and keeps the old ticket',async()=>{
 const row=unknownRow(),old=recoveryFixture(row),fresh=recoveryFixture(row,content(),true),storage=new Map([['yunzhan.apache-cc-archive.v1.'+actor+'.retain',JSON.stringify({id:row.id,sha256:old.snapshot_sha256})]]);let currentRow=row,posted=0;
 const t=component({storage,props:{active:true},api:async(path,method,body)=>{
  if(method==='POST'){posted++;assert.equal(body.sha256,fresh.snapshot_sha256);assert.ok(storage.has('yunzhan.apache-cc-archive.v1.'+actor+'.retain.prior'));currentRow=retainedRow(fresh);return currentRow;}
  if(path.endsWith('/recovery'))return {...fresh,record:currentRow};return fixture([currentRow]);
 }});
 try{await settle();assert.equal(posted,0);assert.ok(t.logic.pendingRetention.value);assert.equal(t.logic.recovery.value.snapshot_sha256,fresh.snapshot_sha256);await t.logic.retainUnknown();assert.equal(posted,1);assert.equal(t.logic.pendingRetention.value,undefined);assert.deepEqual(JSON.parse(storage.get('yunzhan.apache-cc-archive.v1.'+actor+'.retain.prior')),[{id:row.id,sha256:old.snapshot_sha256}]);}finally{t.stop();}
});

test('a different verified retention receipt never clears an older request without explicit acknowledgement',async()=>{
 const proof=recoveryFixture(),row=retainedRow(proof),original={id:row.id,sha256:'e'.repeat(64)},storage=new Map([['yunzhan.apache-cc-archive.v1.'+actor+'.retain',JSON.stringify(original)]]);
 const t=component({storage,props:{active:true},api:async(path)=>path.endsWith('/recovery')?{...proof,record:row}:fixture([row])});
 try{await settle();assert.equal(t.logic.known.value,true);assert.deepEqual(vue.toRaw(t.logic.pendingRetention.value),original);assert.equal(t.logic.canArchive.value,false);await t.logic.acknowledgeObservedRetention();assert.equal(t.calls.filter(x=>x[1]==='POST').length,0);assert.equal(t.logic.pendingRetention.value,undefined);assert.deepEqual(JSON.parse(storage.get('yunzhan.apache-cc-archive.v1.'+actor+'.retain.prior')),[original]);}finally{t.stop();}
});

test('a corrupt recovery snapshot or unavailable browser storage cannot authorize retention',async()=>{
 for(const denied of [false,true]){
  const row=unknownRow(),proof=recoveryFixture(row),t=component({storageFailure:denied,props:{active:true},api:async(path)=>path.endsWith('/recovery')?{...proof,snapshot_sha256:denied?proof.snapshot_sha256:'0'.repeat(64)}:fixture([row])});
  try{await settle();await t.logic.inspectRecovery(row);await t.logic.retainUnknown();assert.equal(t.calls.filter(x=>x[1]==='POST').length,0);assert.ok(denied?t.logic.storageError.value:t.logic.error.value);}finally{t.stop();}
 }
});

test('retained original data downloads as unknown evidence with exact bytes while absent data never becomes a fake backup',async()=>{
 const data=content(),proof=recoveryFixture(undefined,data),row=retainedRow(proof),t=component({props:{active:true},api:async(path)=>{
  if(path.endsWith('/archives'))return fixture([row]);if(path.endsWith('/'+row.id))return row;
  const part=Number(path.split('/').at(-1)),chunk=data.slice(part*262144,(part+1)*262144);
  return {archive_id:row.id,part,offset:part*262144,bytes:chunk.length,total_bytes:data.length,sha256:row.retained.archive.sha256,data_base64:Buffer.from(chunk).toString('base64'),raw_original_private_log:true,tail_incomplete:null,original_outcome_unknown:true};
 }});
 try{await settle();await t.logic.download(row);assert.equal(t.downloaded.length,1);assert.deepEqual(new Uint8Array(await t.downloaded[0].arrayBuffer()),data);assert.match(t.logic.receipt.value,/不能代表原归档已成功/);}finally{t.stop();}
 const emptyProof={...proof,snapshot:{format:2,id:row.id,files:{},source_identity_only:true}};emptyProof.snapshot_sha256=guards.ccSnapshotSHA(emptyProof.snapshot);const emptyRow=retainedRow(emptyProof);
 const noData=component({props:{active:true},api:async()=>fixture([emptyRow])});try{await settle();await noData.logic.download(emptyRow);assert.equal(noData.downloaded.length,0);assert.equal(noData.calls.length,1);}finally{noData.stop();}
});

test('history transfer keeps all files and releases one active slot; a lost reply is never automatically replayed',async()=>{
 const row=entry(),proof=historyFixture(row),storage=new Map();let moved=false,posts=0;
 const api=async(path,method,body)=>{
  if(method==='POST'){posts++;assert.equal(body.sha256,proof.snapshot_sha256);assert.equal(body.confirm_preserve,true);assert.ok(storage.has('yunzhan.apache-cc-archive.v1.'+actor+'.history'));moved=true;throw Error('owned lost transfer reply');}
  if(path.endsWith('/history'))return {...proof,history:moved};const inventory=fixture(moved?[]:[row]);if(moved)inventory.history=[row];return inventory;
 };
 let t=component({api,storage,props:{active:true}});
 try{await settle();await t.logic.preserveHistory(row);assert.equal(posts,1);assert.equal(t.logic.inventory.value.archives.length,0);assert.equal(t.logic.inventory.value.history.length,1);assert.equal(t.logic.pendingHistory.value,undefined);assert.match(t.logic.receipt.value,/未再次移动/);}finally{t.stop();}
 t=component({api,storage,props:{active:true}});try{await settle();await t.logic.preserveHistory(row);assert.equal(posts,1);assert.equal(t.logic.inventory.value.history.length,1);}finally{t.stop();}
});

test('history refusal, foreign receipts and full history never remove original rows or clear the original ticket',async()=>{
 const row=entry(),proof=historyFixture(row),storage=new Map();let posts=0;
 const t=component({storage,props:{active:true},api:async(path,method)=>{
  if(method==='POST'){posts++;return {record:row,snapshot_sha256:proof.snapshot_sha256,history:true,current_log_untouched:true,no_delete:false};}
  if(path.endsWith('/history'))return proof;return fixture([row]);
 }});
 try{await settle();await t.logic.preserveHistory(row);assert.equal(posts,1);assert.equal(t.logic.inventory.value.archives.length,1);assert.ok(t.logic.pendingHistory.value);await t.logic.refresh();assert.equal(posts,1);assert.equal(t.logic.canArchive.value,false);t.logic.inventory.value.history=Array.from({length:32},(_,i)=>entry({request_id:i.toString(16).padStart(32,'0'),expected_revision:7,allow_incomplete:false}));await t.logic.preserveHistory(row);assert.equal(posts,1);}finally{t.stop();}
});

test('the real WAF parent supplies the account identity and normal release builds require these behavior tests',()=>{
 const manager=readFileSync(new URL('../web/src/AppModuleManager.vue',import.meta.url),'utf8'),packaging=readFileSync(new URL('../packaging/build-release.sh',import.meta.url),'utf8');
 assert.ok(/<WafWorkspace[^>]*:actor="geoActor"[^>]*engine="apache-waf"/.test(manager),"actual Apache parent must pass the current account");assert.match(packaging,/node --test scripts\/test-apache-cc-archives\.mjs/);
});

test('historical PHP source pins remove only the exact Apache dependency check without weakening a prior assertion',()=>{
 const current=readFileSync(new URL('../internal/executor/install_linux.go',import.meta.url),'utf8'),before=beforeApacheBuildDependencyAdmission(current);
 assert.equal(current.includes('libaprutil1-dev'),true);assert.equal(before.includes('libaprutil1-dev'),false);
 assert.equal(before.includes('正在从官方站点下载精确版本源码并校验完整性'),false);
 assert.throws(()=>beforeApacheBuildDependencyAdmission(current.replace('正在从官方站点下载精确版本源码并校验完整性','unreviewed progress')));
 assert.equal(before.includes('waitRuntimePHPWorkerMemory(ctx, release)'),true);
 for(const text of [before,current.replace('libaprutil1-dev','foreign-dev'),current.replace('\tbase, e := prepareRuntimeBuildDirectory(id)','\tbase, e := prepareRuntimeBuildDirectory(id)\n'+current.slice(current.indexOf('\tif r.Family == "apache" &&'),current.indexOf('\tbase, e := prepareRuntimeBuildDirectory(id)')))])assert.throws(()=>beforeApacheBuildDependencyAdmission(text));
 const changed=current.replace('return 4 * time.Hour','return 8 * time.Hour');assert.notEqual(beforeApacheBuildDependencyAdmission(changed),before);
});


test('independent copies reject same-inode provenance, legacy receipts and unbound source status',()=>{
 const row=entry();
 assert.equal(guards.ccArchiveEntry({...row,source_status:'changed-after-copy'}),true);
 for(const bad of [
  {...row,source_status:undefined},
  {...row,source_status:'matches-anything'},
  {...row,intent:{...row.intent,format:1}},
  {...row,prepared:{...row.prepared,format:1}},
  {...row,completed:{...row.completed,format:1}},
  {...row,prepared:{...row.prepared,archive:{...row.prepared.archive,inode:row.intent.source.inode}}},
  {...row,prepared:{...row.prepared,archive:{...row.prepared.archive,inode:row.prepared.fresh.inode}}},
  {...row,completed:{...row.completed,archive:{...row.completed.archive,inode:row.intent.source.inode}}},
 ])assert.equal(guards.ccArchiveEntry(bad),false);
 const proof=recoveryFixture();
 const source={...row.intent.source,bytes:0,sha256:empty};
 proof.snapshot.files['next.log']=source;proof.snapshot_sha256=guards.ccSnapshotSHA(proof.snapshot);
 const kept=retainedRow(proof);kept.source_status='not-authoritative';kept.retained.preserved_source={...source,uid:0,gid:0};
 assert.equal(guards.ccArchiveEntry(kept),true);
 assert.equal(guards.ccArchiveEntry({...kept,source_status:'matches-witness'}),false);
 assert.equal(guards.ccArchiveEntry({...kept,retained:{...kept.retained,preserved_source:undefined}}),false);
 for(const patch of [{source_identity_only:false},{format:1},{files:{...proof.snapshot.files,'data.log':row.intent.source}},{files:{...proof.snapshot.files,'next.log':row.intent.source}}]){
  const snapshot={...proof.snapshot,...patch};assert.equal(guards.ccRecovery({...proof,snapshot,snapshot_sha256:guards.ccSnapshotSHA(snapshot)},row.id),false);
 }
});


test('Root service groups remain visible in completed inventory, request and history codecs',()=>{
 for(const group of [0,987,65534]){
  const row=entry(undefined,content(),group),proof=historyFixture(row);
  proof.snapshot.files['data.log']=structuredClone(row.completed.archive);proof.snapshot.files['intent.json'].gid=group;proof.snapshot_sha256=guards.ccSnapshotSHA(proof.snapshot);
  assert.equal(guards.ccArchiveEntry(row),true);assert.equal(guards.ccArchiveInventory(fixture([row])),true);
  assert.equal(guards.ccRequestObservation({kind:'archive',record:row,read_only:true},row.intent.request),true);
  assert.equal(guards.ccHistoryObservation(proof,row.id),true);
  const mismatch={...row,completed:{...row.completed,archive:{...row.completed.archive,gid:group+1}}};assert.equal(guards.ccArchiveEntry(mismatch),false);
  assert.equal(row.completed.archive.gid,group);
 }
});

test('mixed Root groups retain exact data and already-private source witnesses in both directions',()=>{
 for(const [writer,retainer]of [[987,0],[0,987]])for(const privateSource of [false,true]){
  const proof=recoveryFixture(undefined,content(),false,writer),base=entry();
  proof.snapshot.files['next.log']={...base.intent.source,uid:privateSource?0:33,gid:privateSource?writer:33,bytes:0,sha256:empty};proof.snapshot_sha256=guards.ccSnapshotSHA(proof.snapshot);
  const row=retainedRow(proof,retainer);row.source_status='not-authoritative';row.retained.preserved_source={...proof.snapshot.files['next.log'],uid:0,gid:privateSource?writer:retainer};
  assert.equal(guards.ccRecovery(proof,row.id),true);assert.equal(guards.ccArchiveEntry(row),true);assert.equal(guards.ccArchiveInventory(fixture([row])),true);
  assert.equal(row.retained.archive.gid,writer);assert.equal(row.retained.retention_intent.gid,retainer);assert.equal(guards.ccSnapshotSHA(row.retained.snapshot),proof.snapshot_sha256);
  const dataBad=structuredClone(row);dataBad.retained.archive.gid=writer+1;assert.equal(guards.ccArchiveEntry(dataBad),false);
  if(privateSource){const sourceBad=structuredClone(row);sourceBad.retained.preserved_source.gid=writer+1;assert.equal(guards.ccArchiveEntry(sourceBad),false);}
  else{const workerBad=structuredClone(row);workerBad.retained.snapshot.files['next.log'].gid=34;workerBad.retained.snapshot_sha256=guards.ccSnapshotSHA(workerBad.retained.snapshot);assert.equal(guards.ccArchiveEntry(workerBad),false);}
 }
});

test('every private GID remains in canonical snapshot hashes and foreign Root ownership is refused',()=>{
 const proof=recoveryFixture(undefined,content(),false,987),original=proof.snapshot_sha256;
 for(const name of Object.keys(proof.snapshot.files)){
  const bad=structuredClone(proof);bad.snapshot.files[name].gid++;assert.notEqual(guards.ccSnapshotSHA(bad.snapshot),original);assert.equal(guards.ccRecovery(bad,bad.record.id),false);
  const foreign=structuredClone(proof);foreign.snapshot.files[name].uid=33;foreign.snapshot_sha256=guards.ccSnapshotSHA(foreign.snapshot);assert.equal(guards.ccRecovery(foreign,foreign.record.id),false);
 }
});

test('actual Vue archive flow accepts a Root service group and verifies both original download chunks',async()=>{
 const data=content(),row=entry(undefined,data,987);let rows=[];
 const t=component({api:async(path,method,request)=>{
  if(method==='POST'){const current=entry(request,data,987);rows=[current];return current;}
  if(path.endsWith('/archives'))return fixture(rows.length?rows:[row]);
  const selected=rows[0]??row;if(path.endsWith('/'+selected.id))return selected;
  const part=Number(path.split('/').at(-1)),chunk=data.slice(part*262144,(part+1)*262144);
  return {archive_id:selected.id,part,offset:part*262144,bytes:chunk.length,total_bytes:data.length,sha256:selected.completed.archive.sha256,data_base64:Buffer.from(chunk).toString('base64'),raw_original_private_log:true,tail_incomplete:false,original_outcome_unknown:false};
 }});
 try{t.props.active=true;await settle();assert.equal(t.logic.known.value,true);assert.equal(t.logic.error.value,'');await t.logic.archive();assert.equal(t.calls.filter(x=>x[1]==='POST').length,1);const actual=t.logic.inventory.value.archives[0];assert.equal(actual.completed.archive.gid,987);await t.logic.download(actual);assert.equal(t.downloaded.length,1);assert.deepEqual(new Uint8Array(await t.downloaded[0].arrayBuffer()),data);}finally{t.stop();}
});

test('actual Vue mixed-group retention keeps the original unknown outcome and original data group',async()=>{
 const proof=recoveryFixture(undefined,content(),false,987);let row=proof.record,posts=0;
 const t=component({props:{active:true},api:async(path,method,body)=>{
  if(method==='POST'){posts++;assert.equal(body.sha256,proof.snapshot_sha256);row=retainedRow(proof,0);return row;}
  if(path.endsWith('/recovery'))return {...proof,record:row};return fixture([row]);
 }});
 try{await settle();await t.logic.inspectRecovery(row);assert.equal(t.logic.recovery.value.snapshot.files['data.log'].gid,987);await t.logic.retainUnknown();assert.equal(posts,1);assert.equal(t.logic.inventory.value.archives[0].state,'retained-unknown');assert.equal(t.logic.inventory.value.archives[0].retained.archive.gid,987);assert.equal(t.logic.inventory.value.archives[0].retained.retention_intent.gid,0);assert.match(t.logic.receipt.value,/原归档结果仍未知/);}finally{t.stop();}
});
