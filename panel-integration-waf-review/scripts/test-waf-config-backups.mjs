import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import ts from '../web/node_modules/typescript/lib/typescript.js';
import {archiveWafConfigBackup,decodeWafConfigBackup,decodeWafConfigBackups,decodeWafConfigBackupSlots,decodeWafConfigBackupArchiveResult,decodeWafConfigBackupArchiveRecovery,readWafConfigBackups,readWafConfigBackupSlots,readWafConfigBackupSnapshot,readWafConfigBackupArchive,readWafConfigBackupArchiveRecovery,wafConfigBackupArchiveInput,wafConfigBackupArchiveRecoveredInput} from '../web/src/wafConfigBackups.ts';
const row=()=>({id:'1'.repeat(32),created_at:'2026-10-11T00:00:00Z',files:5,bytes:123,sha256:'a'.repeat(64)});
const valid=()=>({available:true,entries:[row()],bytes:123,count_max:100,scan_max_bytes:134217728,read_only:true,message:'closed fixture, not native inventory'});
const recovery=()=>({pending:null,read_only:true});
const pending=()=>({resource_id:row().id,expected_sha:row().sha256,created_at:'2026-10-11T00:00:00Z'});
const emptyOrInventory=path=>path==='/software/nginx-waf/config-backup-archive-request'?recovery():valid();
test('actual reader calls only the fixed read-only inventory endpoint',async()=>{
 const value=valid();assert.deepEqual(decodeWafConfigBackups(value),value);
 assert.deepEqual(await readWafConfigBackups(async path=>{assert.equal(path,'/software/nginx-waf/config-backups');return value;},()=>true),value);
 const unavailable={...valid(),available:false,entries:[],bytes:0};assert.equal(decodeWafConfigBackups(unavailable).available,false);
 assert.equal(decodeWafConfigBackups({...unavailable,available:true}).entries.length,0);
});
test('closed inventory shape, logical work bounds and ambiguous counts fail closed',()=>{
 for(const value of [null,[],{}, {...valid(),secret:'/private'}, {...valid(),available:null}, {...valid(),read_only:false}, {...valid(),entries:null}, {...valid(),count_max:101}, {...valid(),scan_max_bytes:1}, {...valid(),bytes:124}, {...valid(),available:false}, {...valid(),message:'x'.repeat(1025)}, {...valid(),entries:Array(101).fill(row())}, {...valid(),entries:[row(),row()],bytes:246}])assert.throws(()=>decodeWafConfigBackups(value));
 for(const change of [{files:4},{files:4097},{files:NaN},{files:5.1},{bytes:0},{bytes:9*1048576+1},{sha256:'A'.repeat(64)},{id:'BAD'},{created_at:'bad'},{source:'/private'}])assert.throws(()=>decodeWafConfigBackups({...valid(),entries:[{...row(),...change}]}));
});
test('failed read and disposed original workspace cannot publish inventory',async()=>{
 let calls=0;await assert.rejects(readWafConfigBackups(async()=>{calls++;throw new Error('unavailable');},()=>true),/unavailable/);assert.equal(calls,1);
 await assert.rejects(readWafConfigBackups(async()=>{assert.fail('disposed before read');},()=>false));
 let live=true;await assert.rejects(readWafConfigBackups(async()=>{live=false;return valid();},()=>live),/已关闭/);
});
function component(){
 const source=readFileSync(new URL('../web/src/WafConfigBackups.vue',import.meta.url),'utf8');
 const actual=source.slice(source.indexOf('async function refresh()'),source.indexOf('watch(()=>props.active'));
 const js=ts.transpileModule(actual,{compilerOptions:{target:ts.ScriptTarget.ES2022}}).outputText;
 const b={props:{active:true,api:async path=>emptyOrInventory(path)},disposed:false,generation:0,inventory:{value:valid()},error:{value:''},busy:{value:false},slots:{value:undefined},archived:{value:undefined},selected:{value:undefined},confirmation:{value:''},receipt:{value:''},evidence:{value:''},pendingArchive:{value:undefined},recovery:{value:recovery()},recoveryError:{value:''},recoveryConflict:{value:false},archiveWafConfigBackup,decodeWafConfigBackup,readWafConfigBackups,readWafConfigBackupSlots,readWafConfigBackupSnapshot,readWafConfigBackupArchive,readWafConfigBackupArchiveRecovery,wafConfigBackupArchiveInput,wafConfigBackupArchiveRecoveredInput};
 return {b,...new Function('b','with(b){'+js+';return {refresh,invalidate,loadSlots,choose,verifySnapshot,loadArchive,archiveSelected,inspectOriginal};}')(b)};
}
test('actual component clears stale counts while refreshing and keeps failures unknown',async()=>{
 const {b,refresh}=component();b.props.api=async()=>{assert.equal(b.inventory.value,undefined);assert.equal(b.busy.value,true);throw new Error('scan refused');};await refresh();assert.equal(b.inventory.value,undefined);assert.equal(b.busy.value,false);assert.equal(b.error.value,'scan refused');
 b.props.api=async path=>emptyOrInventory(path);await refresh();assert.equal(b.inventory.value.entries.length,1);assert.equal(b.error.value,'');assert.deepEqual(b.recovery.value,recovery());
});
test('actual close/new activation prevents stale response and finally from touching new inventory',async()=>{
 const {b,refresh,invalidate}=component();let resolve;
 b.props.api=()=>new Promise(r=>{resolve=r;});const pending=refresh();b.props.active=false;invalidate();assert.equal(b.inventory.value,undefined);assert.equal(b.busy.value,false);
 b.props.active=true;b.props.api=async path=>path==='/software/nginx-waf/config-backup-archive-request'?recovery():({...valid(),entries:[],bytes:0});await refresh();resolve(recovery());await pending;
 assert.equal(b.inventory.value.entries.length,0);assert.equal(b.error.value,'');assert.equal(b.busy.value,false);
 b.props.active=false;await refresh();b.props.active=true;b.disposed=true;await refresh();assert.equal(b.inventory.value.entries.length,0);
});
test('workspace binds only Nginx tab and normal build executes this control-flow gate',()=>{
 const source=readFileSync(new URL('../web/src/WafWorkspace.vue',import.meta.url),'utf8');assert.match(source,/<el-tab-pane v-if="!apache" label="配置备份" name="config-backups"><WafConfigBackups :api="api" :active="tab==='config-backups'"\/>/);
 const component=readFileSync(new URL('../web/src/WafConfigBackups.vue',import.meta.url),'utf8');assert.match(component,/不删除、不导出配置正文、不回滚或重载网站/);assert.match(component,/不是磁盘硬配额/);assert.match(component,/目录数量不等于完整快照核验数量/);assert.match(component,/重开界面仅只读恢复/);assert.match(component,/未到达服务端的请求仅保留在本工作区/);assert.doesNotMatch(component,/"DELETE"/);
 assert.match(readFileSync(new URL('../packaging/build-release.sh',import.meta.url),'utf8'),/test-waf-config-backups\.mjs/);
});

const slots=()=>({available:true,ids:[row().id],count_max:100,read_only:true,contents_verified:false,message:'closed directory fixture, not complete content'});
const input=()=>wafConfigBackupArchiveInput(row(),'ARCHIVE NGINX CONFIG '+row().id);
const result=(replayed=false)=>({snapshot:row(),archived:true,replayed,records_retained:true,configuration_changed:false});
test('directory IDs never impersonate content verification and all read paths are fixed',async()=>{
 assert.deepEqual(decodeWafConfigBackupSlots(slots()),slots());
 for(const bad of [{...slots(),contents_verified:true},{...slots(),contents_verified:null},{...slots(),ids:null},{...slots(),ids:[row().id,row().id]},{...slots(),available:false},{...slots(),secret:'/private'},{...slots(),ids:['BAD']}])assert.throws(()=>decodeWafConfigBackupSlots(bad));
 assert.deepEqual(await readWafConfigBackupSlots(async path=>{assert.equal(path,'/software/nginx-waf/config-backup-slots');return slots();},()=>true),slots());
 for(const archived of [false,true])assert.deepEqual(await readWafConfigBackupSnapshot(async path=>{assert.equal(path,'/software/nginx-waf/'+(archived?'config-backup-archive/':'config-backups/')+row().id);return row();},()=>true,row().id,archived),row());
 await assert.rejects(readWafConfigBackupSnapshot(async()=>{assert.fail('invalid ID sent');},()=>true,'/private'));
 await assert.rejects(readWafConfigBackupSnapshot(async()=>({...row(),id:'2'.repeat(32)}),()=>true,row().id));
 assert.deepEqual(await readWafConfigBackupArchive(async path=>{assert.equal(path,'/software/nginx-waf/config-backup-archive');return valid();},()=>true),valid());
});
test('explicit archive has one fixed POST and original consent, identity, closed digest receipt',async()=>{
 const original=input();assert.equal(Object.isFrozen(original),true);
 assert.throws(()=>wafConfigBackupArchiveInput(row(),'DELETE '+row().id));
 assert.deepEqual(await archiveWafConfigBackup(async(path,method,body)=>{assert.equal(path,'/software/nginx-waf/archive-config-backup');assert.equal(method,'POST');assert.deepEqual(body,original);return result();},()=>true,original),result());
 for(const bad of [{...result(),archived:null},{...result(),replayed:null},{...result(),records_retained:false},{...result(),configuration_changed:true},{...result(),secret:'/private'},{...result(),snapshot:{...row(),sha256:'b'.repeat(64)}},{...result(),snapshot:{...row(),source:'/private'}}])assert.throws(()=>decodeWafConfigBackupArchiveResult(bad,original));
 let calls=0;await assert.rejects(archiveWafConfigBackup(async()=>{calls++;throw new Error('reply lost');},()=>true,original),/reply lost/);assert.equal(calls,1);
 let live=true;await assert.rejects(archiveWafConfigBackup(async()=>{live=false;return result();},()=>live,original),/已关闭/);
 await assert.rejects(archiveWafConfigBackup(async()=>{assert.fail('old context sent mutation');},()=>false,original));
});
test('actual component fallback exposes unverified IDs only and single verification stays separate',async()=>{
 const {b,loadSlots,verifySnapshot,loadArchive}=component();b.inventory.value=undefined;
 b.props.api=async path=>{assert.equal(path,'/software/nginx-waf/config-backup-slots');return slots();};await loadSlots();assert.equal(b.slots.value.contents_verified,false);assert.equal(b.inventory.value,undefined);assert.equal(b.selected.value,undefined);
 b.props.api=async path=>{assert.equal(path,'/software/nginx-waf/config-backups/'+row().id);return row();};await verifySnapshot(row().id);assert.deepEqual(b.selected.value,row());assert.equal(b.inventory.value,undefined);
 b.props.api=async()=>({...row(),source:'/private'});await verifySnapshot(row().id);assert.equal(b.selected.value,undefined);assert.ok(b.error.value);
 b.props.api=async()=>valid();await loadArchive();assert.equal(b.archived.value.entries.length,1);b.props.api=async()=>{assert.equal(b.archived.value,undefined);throw new Error('archive scan refused');};await loadArchive();assert.equal(b.archived.value,undefined);assert.equal(b.error.value,'archive scan refused');
});
test('actual component keeps original ticket BEFORE unknown POST and draft cannot replace it',async()=>{
 const {b,choose,archiveSelected,inspectOriginal}=component();choose(row());b.confirmation.value=input().confirm;let calls=0;
 b.props.api=async(path,method,body)=>{calls++;assert.deepEqual(b.pendingArchive.value.input,input());assert.deepEqual(body,input());assert.equal(method,'POST');throw new Error('reply lost');};await archiveSelected();assert.equal(calls,1);assert.deepEqual(b.pendingArchive.value.input,input());assert.equal(b.receipt.value,'');
 choose({...row(),id:'2'.repeat(32)});b.confirmation.value='different draft';assert.deepEqual(b.pendingArchive.value.input,input());
 b.props.api=async(path,method)=>{calls++;assert.equal(path,'/software/nginx-waf/config-backup-archive/'+row().id);assert.equal(method,undefined);return row();};await inspectOriginal();assert.equal(calls,2);assert.deepEqual(b.pendingArchive.value.input,input());assert.match(b.evidence.value,/不代表原操作回执或审计已完成/);assert.equal(b.receipt.value,'');
 b.props.api=async(path,method,body)=>{calls++;assert.equal(method,'POST');assert.deepEqual(body,input());return result(true);};await archiveSelected();assert.equal(calls,3);assert.equal(b.pendingArchive.value,undefined);assert.match(b.receipt.value,/原身份重试/);assert.equal(b.inventory.value,undefined);assert.equal(b.archived.value,undefined);
});
test('actual component wrong digest and missing archived evidence remain original unknown',async()=>{
 const {b,choose,archiveSelected,inspectOriginal}=component();choose(row());b.confirmation.value=input().confirm;
 b.props.api=async()=>({...result(),snapshot:{...row(),sha256:'b'.repeat(64)}});await archiveSelected();assert.deepEqual(b.pendingArchive.value.input,input());assert.equal(b.receipt.value,'');
 b.props.api=async()=>({...row(),sha256:'b'.repeat(64)});await inspectOriginal();assert.equal(b.evidence.value,'');assert.ok(b.error.value);assert.deepEqual(b.pendingArchive.value.input,input());
 b.props.api=async()=>{throw new Error('archived snapshot unavailable; no claim of no move');};await inspectOriginal();assert.equal(b.receipt.value,'');assert.deepEqual(b.pendingArchive.value.input,input());
});
test('actual close and reopened workspace cannot receive late archive success or issue auto POST',async()=>{
 const {b,choose,archiveSelected,invalidate,refresh}=component();choose(row());b.confirmation.value=input().confirm;let resolve,calls=0;
 b.props.api=()=>{calls++;return new Promise(r=>{resolve=r;});};const original=archiveSelected();assert.deepEqual(b.pendingArchive.value.input,input());
 b.props.active=false;invalidate();assert.equal(b.receipt.value,'');b.props.active=true;b.props.api=async path=>{calls++;assert.ok(['/software/nginx-waf/config-backup-archive-request','/software/nginx-waf/config-backups'].includes(path));return path.endsWith('archive-request')?recovery():{...valid(),entries:[],bytes:0};};await refresh();resolve(result());await original;
 assert.equal(calls,3);assert.equal(b.inventory.value.entries.length,0);assert.equal(b.busy.value,false);assert.equal(b.receipt.value,'');assert.deepEqual(b.pendingArchive.value.input,input());
 b.disposed=true;await archiveSelected();assert.equal(calls,3);
});

test('actor-bound recovery is a closed UTC identity, not a native result or a POST',async()=>{
 const value={pending:pending(),read_only:true};assert.deepEqual(decodeWafConfigBackupArchiveRecovery(value),value);assert.deepEqual(decodeWafConfigBackupArchiveRecovery(recovery()),recovery());
 for(const bad of [null,{},[],{...value,read_only:false},{...value,pending:undefined},{...value,actor_id:'2'.repeat(32)},{...value,pending:{...pending(),confirm:input().confirm}},{...value,pending:{...pending(),expected_sha:'A'.repeat(64)}},{...value,pending:{...pending(),created_at:'2026-02-30T00:00:00Z'}},{...value,pending:{...pending(),created_at:'2026-10-11T00:00:00+00:00'}},{...value,pending:{...pending(),created_at:'2026-10-11T00:00:00.000Z'}},{...value,pending:{...pending(),resource_id:'/private'}}])assert.throws(()=>decodeWafConfigBackupArchiveRecovery(bad));
 let calls=0;assert.deepEqual(await readWafConfigBackupArchiveRecovery(async(path,...args)=>{calls++;assert.equal(path,'/software/nginx-waf/config-backup-archive-request');assert.deepEqual(args,[]);return value;},()=>true),value);assert.equal(calls,1);
 const original=wafConfigBackupArchiveRecoveredInput(pending());assert.deepEqual(original,input());assert.ok(Object.isFrozen(original));
 await assert.rejects(readWafConfigBackupArchiveRecovery(async()=>{assert.fail('closed read');},()=>false));let live=true;await assert.rejects(readWafConfigBackupArchiveRecovery(async()=>{live=false;return value;},()=>live));
});
test('actual reopening recovers only the committed original and requires explicit same-identity retry',async()=>{
 const {b,refresh,archiveSelected}=component();const paths=[];
 b.props.api=async(path,method,body)=>{paths.push([path,method]);if(path.endsWith('archive-request'))return {pending:pending(),read_only:true};if(path.endsWith('config-backups'))return valid();assert.equal(method,'POST');assert.deepEqual(body,input());return result(true);};
 await refresh();assert.deepEqual(paths,[['/software/nginx-waf/config-backup-archive-request',undefined],['/software/nginx-waf/config-backups',undefined]]);assert.deepEqual(b.pendingArchive.value.input,input());assert.equal(b.receipt.value,'');assert.equal(b.evidence.value,'');
 await archiveSelected();assert.equal(paths.length,3);assert.equal(b.pendingArchive.value,undefined);assert.match(b.receipt.value,/原身份重试/);assert.equal(b.recovery.value,undefined);
});
test('failed or malformed recovery cannot impersonate absence or permit a mutation',async()=>{
 for(const value of [undefined,{pending:pending(),read_only:false},{pending:{...pending(),expected_sha:'BAD'},read_only:true}]){
  const {b,refresh,choose,archiveSelected}=component();let posts=0;
  b.props.api=async(path,method)=>{if(method){posts++;assert.fail('unknown recovery issued POST');}if(path.endsWith('archive-request')){if(value===undefined)throw new Error('recovery unavailable');return value;}return valid();};
  await refresh();assert.equal(b.recovery.value,undefined);assert.ok(b.recoveryError.value);assert.equal(b.inventory.value.entries.length,1);choose(row());assert.equal(b.selected.value,undefined);b.selected.value=row();b.confirmation.value=input().confirm;await archiveSelected();assert.equal(posts,0);assert.equal(b.pendingArchive.value,undefined);assert.equal(b.receipt.value,'');
 }
});
test('explicit absence and a different server identity never overwrite the original unknown request',async()=>{
 const {b,refresh,archiveSelected}=component();b.pendingArchive.value={input:input()};
 b.props.api=async path=>emptyOrInventory(path);await refresh();assert.deepEqual(b.pendingArchive.value.input,input());assert.equal(b.receipt.value,'');assert.equal(b.recoveryConflict.value,false);
 const other={...pending(),resource_id:'2'.repeat(32),expected_sha:'b'.repeat(64)};let posts=0;
 b.props.api=async(path,method)=>{if(method)posts++;return path.endsWith('archive-request')?{pending:other,read_only:true}:valid();};await refresh();assert.deepEqual(b.pendingArchive.value.input,input());assert.deepEqual(b.recovery.value.pending,other);assert.equal(b.recoveryConflict.value,true);assert.match(b.recoveryError.value,/不替换/);await archiveSelected();assert.equal(posts,0);
});
test('late recovery after close or a fresh account cannot publish an identity or chain an inventory read',async()=>{
 const {b,refresh,invalidate}=component();let resolve;const oldPaths=[];
 b.props.api=path=>{oldPaths.push(path);return new Promise(r=>{resolve=r;});};const old=refresh();b.props.active=false;invalidate();resolve({pending:pending(),read_only:true});await old;assert.equal(oldPaths.length,1);assert.equal(b.pendingArchive.value,undefined);assert.equal(b.inventory.value,undefined);assert.equal(b.busy.value,false);
 const fresh=component();fresh.b.props.api=async path=>emptyOrInventory(path);await fresh.refresh();assert.equal(fresh.b.pendingArchive.value,undefined);assert.equal(fresh.b.receipt.value,'');
});
