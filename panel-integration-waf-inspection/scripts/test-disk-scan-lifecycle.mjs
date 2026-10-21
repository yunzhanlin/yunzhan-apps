// Actual compiled handlers/transport with explicit synthetic requests. These
// fixtures do not establish installed UI, native cancellation or OS acceptance.
import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import ts from '../web/node_modules/typescript/lib/typescript.js';
const read=p=>readFileSync(new URL('../'+p,import.meta.url),'utf8');
const manager=read('web/src/AppModuleManager.vue'),app=read('web/src/App.vue');
const compile=s=>ts.transpileModule(s,{compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.ESNext}}).outputText;
const {assertFrontendMutationCurrent}=await import('data:text/javascript;base64,'+Buffer.from(compile(read('web/src/frontendRelease.ts'))).toString('base64'));
const handlers=manager.slice(manager.indexOf('async function executeDiskScan('),manager.indexOf('async function execute(action:'));
const cancel=manager.slice(manager.indexOf('function cancelDiskScan('),manager.indexOf('onBeforeUnmount(cancelDiskScan)'));
const defer=()=>{let resolve,reject;const promise=new Promise((a,b)=>{resolve=a;reject=b;});return {promise,resolve,reject};};
function fixture(){
 const calls=[],pending=defer(),original={original_report:true},values={
  definition:{value:{id:'disk-analysis'}},installed:{value:true},installedUnknown:{value:false},busy:{value:false},visible:{value:true},
  diskScanRequest:{value:undefined},diskCancellationRequested:{value:false},diskScanNotice:{value:''},error:{value:''},report:{value:original},reportStateUnknown:{value:false},
  props:{api:async(...args)=>{calls.push(args);return pending.promise;}},inputBody:()=>({site_id:'a'.repeat(32),path:'owned-fixture'}),setReport:value=>{values.report.value=value;},
 };
 const code=compile(cancel+handlers)+'\nreturn {executeDiskScan,readDiskScanReport,cancelDiskScan,setEpoch:value=>{idsAccessGeneration=value;}};';
 const actual=new Function(...Object.keys(values),'idsAccessGeneration',code)(...Object.values(values),7);
 return {values,calls,pending,original,...actual};
}
test('actual disk handler submits exactly one cancellable read and blocks overlap until the original settles',async()=>{
 const f=fixture(),run=f.executeDiskScan();assert.equal(f.values.busy.value,true);assert.equal(f.values.report.value,f.original);assert.equal(f.calls.length,1);
 assert.equal(f.calls[0][0],'/app-modules/disk-analysis/run');assert.equal(f.calls[0][1],'POST');assert.deepEqual(f.calls[0][2],{site_id:'a'.repeat(32),path:'owned-fixture'});assert.equal(f.calls[0][3],undefined);assert(f.calls[0][4] instanceof AbortSignal);assert.equal(f.calls[0][4].aborted,false);
 await f.executeDiskScan();await f.readDiskScanReport();assert.equal(f.calls.length,1);f.pending.resolve({native_fixture:true});await run;assert.deepEqual(f.values.report.value,{native_fixture:true});assert.equal(f.values.busy.value,false);assert.equal(f.values.diskScanRequest.value,undefined);
});
test('actual cancel requests abort once, preserves old report and does not invent server confirmation or retry',async()=>{
 const f=fixture(),run=f.executeDiskScan(),signal=f.calls[0][4];let aborted=0;signal.addEventListener('abort',()=>aborted++);
 f.cancelDiskScan();f.cancelDiskScan();assert.equal(aborted,1);assert.equal(signal.aborted,true);assert.equal(f.values.diskCancellationRequested.value,true);assert.equal(f.values.busy.value,true);assert.match(f.values.diskScanNotice.value,/已请求中断/);assert.match(f.values.diskScanNotice.value,/不能据此确认/);assert.equal(f.values.report.value,f.original);
 f.pending.reject(new DOMException('synthetic client abort','AbortError'));await run;assert.equal(f.values.report.value,f.original);assert.equal(f.values.error.value,'');assert.equal(f.calls.length,1);assert.equal(f.values.busy.value,false);
});
test('late success after abort and success queued just before abort are not published as a fresh confirmed scan',async()=>{
 for(const resolveFirst of [true,false]){
  const f=fixture(),run=f.executeDiskScan();if(resolveFirst)f.pending.resolve({late:true});f.cancelDiskScan();if(!resolveFirst)f.pending.resolve({late:true});await run;
  assert.equal(f.values.report.value,f.original);assert.equal(f.calls.length,1);assert.equal(f.values.busy.value,false);assert.match(f.values.diskScanNotice.value,/取消可能与完成同时发生/);
 }
});
test('ordinary errors remain errors and close/account changes cannot publish an old disk result',async()=>{
 const failure=fixture(),running=failure.executeDiskScan();failure.pending.reject(Error('synthetic native refusal'));await running;assert.equal(failure.values.report.value,failure.original);assert.equal(failure.values.error.value,'synthetic native refusal');
 for(const change of [f=>{f.values.visible.value=false;f.cancelDiskScan();},f=>{f.setEpoch(8);f.cancelDiskScan();}]){
  const f=fixture(),run=f.executeDiskScan();change(f);f.pending.resolve({foreign_context:true});await run;assert.equal(f.values.report.value,f.original);assert.equal(f.values.busy.value,false);
 }
});
function validPage(report={saved:true}){return {definition:{id:'disk-analysis'},status:{id:'disk-analysis',installed:true,healthy:true},report};}
test('actual reconciliation uses only GET of saved report and never a second scan or a cancellation-success claim',async()=>{
 const f=fixture(),run=f.readDiskScanReport();assert.deepEqual(f.calls,[['/app-modules/disk-analysis']]);f.pending.resolve(validPage());await run;assert.deepEqual(f.values.report.value,{saved:true});assert.match(f.values.diskScanNotice.value,/未重新扫描/);assert.match(f.values.diskScanNotice.value,/不单独证明/);assert.equal(f.values.busy.value,false);
 const none=fixture(),empty=none.readDiskScanReport();none.pending.resolve(validPage(null));await empty;assert.equal(none.values.report.value,undefined);
});
test('malformed, unknown and foreign saved-report identities preserve the original and fail closed',async()=>{
 for(const change of [p=>{p.definition.id='task-manager';},p=>{p.status.id='task-manager';},p=>{p.status.installed=false;},p=>{p.status.healthy='true';},p=>{p.status.state_unknown=true;},p=>{p.status.state_unknown=0;},p=>{p.report_state_unknown=true;},p=>{p.report_state_unknown='false';},p=>{delete p.report;}]){
  const f=fixture(),run=f.readDiskScanReport(),page=validPage();change(page);f.pending.resolve(page);await run;assert.equal(f.values.report.value,f.original);assert.match(f.values.error.value,/无法核对/);assert.equal(f.calls.length,1);
 }
 const f=fixture(),run=f.readDiskScanReport();f.setEpoch(8);f.pending.resolve(validPage());await run;assert.equal(f.values.report.value,f.original);assert.equal(f.values.diskScanNotice.value,'');
});
test('actual session-scoped adapter forwards only explicitly supplied abort signal and still rejects obsolete contexts',async()=>{
 const {scopeWorkspaceAPI}=await import('data:text/javascript;base64,'+Buffer.from(compile(read('web/src/deferredWorkspace.ts'))).toString('base64'));
 const rows=[],controller=new AbortController();let current=true;const api=scopeWorkspaceAPI(async(...args)=>{rows.push(args);return {};},()=>current);
 await api('/unrelated','POST',{ordinary:true},'original-key');assert.equal(rows[0].length,4);await api('/app-modules/disk-analysis/run','POST',{},undefined,controller.signal);assert.equal(rows[1][4],controller.signal);
 current=false;await assert.rejects(()=>api('/app-modules/disk-analysis/run','POST',{},undefined,controller.signal),/上下文已改变/);assert.equal(rows.length,2);
 const pending=defer();current=true;const old=scopeWorkspaceAPI(()=>pending.promise,()=>current)('/read','GET',undefined,undefined,controller.signal);current=false;pending.resolve({obsolete:true});await assert.rejects(()=>old,/上下文已改变/);
});
test('actual shared API hands the same AbortSignal to fetch without changing unrelated mutation tickets or retrying',async()=>{
 const code=compile(app.slice(app.indexOf('async function api<T>('),app.indexOf('const overviewReadGate ='))),calls=[];
 const bindings={assertFrontendMutationCurrent,frontendReleaseStatus:{value:{kind:'current'}},csrf:{value:'synthetic-csrf'},accessEpoch:7,registryRequestIdentity:{begin:()=>{throw Error('disk must not create a registry ticket');}},apiURL:path=>'/api'+path,randomId:()=> 'synthetic-request-id',user:{value:'synthetic-user'},accessPlan:{value:{}},accountChanging:{value:false},clearAccessData:()=>{throw Error('unexpected session reset');},fetch:async(...args)=>{calls.push(args);return {ok:true,status:200,json:async()=>({fixture:true})};}};
 const api=new Function(...Object.keys(bindings),code+';return api;')(...Object.values(bindings));const controller=new AbortController();await api('/app-modules/disk-analysis/run','POST',{site_id:'a'.repeat(32)},undefined,controller.signal);assert.equal(calls.length,1);assert.equal(calls[0][1].signal,controller.signal);assert.equal(calls[0][1].headers['X-CSRF-Token'],'synthetic-csrf');assert.equal(calls[0][1].credentials,'same-origin');
 await api('/ordinary','POST',{});assert(!Object.hasOwn(calls[1][1],'signal'));assert.equal(calls.length,2);
});
test('actual routing is disk-run-only, cancel stays outside loading mask, and close/unmount/access loss request abort',()=>{
 const execute=manager.slice(manager.indexOf('async function execute(action:'),manager.indexOf('async function reviewRemoteTicket('));assert.match(execute,/definition\.value\.id === 'disk-analysis' && action === 'run'\) \{ await executeDiskScan\(\); return; \}/);assert.equal((execute.match(/executeDiskScan\(/g)||[]).length,1);
 const footer=manager.slice(manager.indexOf('<template #footer>'));assert.match(footer,/v-if="definition\?\.id==='disk-analysis' && diskScanRequest"[^>]*@click="cancelDiskScan"/);assert.match(footer,/:disabled="diskCancellationRequested"/);assert.match(footer,/@click="readDiskScanReport"/);assert.match(manager,/onBeforeUnmount\(cancelDiskScan\)/);assert.match(manager,/watch\(visible, value => \{ if \(!value\) \{ cancelDiskScan\(\);/);assert.match(manager,/idsAccessGeneration\+\+;cancelDiskScan\(\);/);
 assert.doesNotMatch(handlers,/\/cancel|setInterval|setTimeout|\.abort\(/);assert.match(read('packaging/build-release.sh'),/test-disk-scan-lifecycle\.mjs/);
});
