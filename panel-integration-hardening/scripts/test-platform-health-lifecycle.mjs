// Actual compiled component handlers; synthetic transport, not installed proof.
import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import ts from '../web/node_modules/typescript/lib/typescript.js';
import {spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {platformReadKnown} from '../web/src/platformManagementReceipt.ts';
const source=readFileSync(new URL('../web/src/AppModuleManager.vue',import.meta.url),'utf8');
const compile=s=>ts.transpileModule(s,{compilerOptions:{target:ts.ScriptTarget.ES2022}}).outputText;
const handlers=source.slice(source.indexOf('async function executePlatformHealthRead('),source.indexOf('async function execute(action:'));
const cancel=source.slice(source.indexOf('function cancelPlatformHealthRead('),source.indexOf('onBeforeUnmount(cancelPlatformHealthRead)'));
const list={hosts:[{id:'owned-host',url:'https://owned.invalid',expected_sha:'a'.repeat(64),healthy:false,telemetry_complete:false,error:'HTTPS not verified'}],checked_at:'2026-10-15T20:00:00Z',scope:'communication only'};
function fixture(){
 let resolve,reject;const pending=new Promise((a,b)=>{resolve=a;reject=b;});const calls=[],original={original:true},focus=[];
 const b={definition:{value:{id:'platform-ops'}},installed:{value:true},installedUnknown:{value:false},busy:{value:false},visible:{value:true},platformReadRequest:{value:undefined},platformReadNotice:{value:''},error:{value:''},form:{value:{resource_id:'owned-host',expected_sha:'old'}},selectedPlanID:{value:'owned-host'},platformMutationObservation:{value:{action:'add',requiredRead:'run',state:'unverified'}},report:{value:original},idsAccessGeneration:1,platformReadKnown,nextTick:async()=>{},userErrorAnchor:{value:{scrollIntoView:()=>focus.push('scroll'),focus:()=>focus.push('focus')}},props:{api:async(...args)=>{calls.push(args);return pending;}},setReport:v=>{b.report.value=v;}};
 const actual=new Function('b','with(b){'+compile(cancel+handlers)+';return {executePlatformHealthRead,cancelPlatformHealthRead};}')(b);
 return {b,calls,original,focus,resolve,reject,...actual};
}
test('exact single run carries AbortSignal; a valid complete list alone updates the selected SHA and clears matching uncertainty',async()=>{
 const f=fixture(),running=f.executePlatformHealthRead();await f.executePlatformHealthRead();assert.equal(f.calls.length,1);assert.deepEqual(f.calls[0].slice(0,4),['/app-modules/platform-ops/run','POST',{},undefined]);assert(f.calls[0][4] instanceof AbortSignal);
 f.resolve(structuredClone(list));await running;assert.deepEqual(f.b.report.value,list);assert.equal(f.b.form.value.expected_sha,'a'.repeat(64));assert.equal(f.b.platformMutationObservation.value,undefined);assert.equal(f.b.busy.value,false);
});
test('cancel once, keep old report and pending mutation observation, never resubmit or revoke',async()=>{
 for(const lateSuccess of [false,true]){const f=fixture(),running=f.executePlatformHealthRead();let aborts=0;f.calls[0][4].addEventListener('abort',()=>aborts++);f.cancelPlatformHealthRead();f.cancelPlatformHealthRead();assert.equal(aborts,1);assert.equal(f.b.busy.value,true);if(lateSuccess)f.resolve(list);else f.reject(new DOMException('synthetic abort','AbortError'));await running;assert.equal(f.b.report.value,f.original);assert.equal(f.b.form.value.expected_sha,'old');assert.equal(f.b.platformMutationObservation.value.state,'unverified');assert.match(f.b.platformReadNotice.value,/取消可能与完成同时发生/);assert.equal(f.b.error.value,'');assert.equal(f.calls.length,1);assert.equal(f.b.busy.value,false);}
});
test('close, account loss and foreign module discard late replies without changing the old report',async()=>{
 for(const alter of [f=>{f.b.visible.value=false;},f=>{f.b.idsAccessGeneration++;}]){const f=fixture(),running=f.executePlatformHealthRead();alter(f);f.cancelPlatformHealthRead();f.resolve(list);await running;assert.equal(f.b.report.value,f.original);assert.equal(f.b.platformMutationObservation.value.state,'unverified');assert.equal(f.b.busy.value,false);}
 const wrong=fixture();wrong.b.definition.value.id='user-manager';await wrong.executePlatformHealthRead();assert.equal(wrong.calls.length,0);
});
test('errors or partial lists preserve old report and uncertainty, while errors remain visible and focused',async()=>{
 for(const corrupt of [false,true]){const f=fixture(),running=f.executePlatformHealthRead();if(corrupt)f.resolve({...list,partial:true});else f.reject(Error('synthetic HTTPS refusal'));await running;assert.equal(f.b.report.value,f.original);assert.equal(f.b.form.value.expected_sha,'old');assert.equal(f.b.platformMutationObservation.value.state,'unverified');assert(f.b.error.value);assert.deepEqual(f.focus,['scroll','focus']);assert.equal(f.calls.length,1);assert.match(f.b.platformReadNotice.value,/原快照/);}
 const f=fixture();f.b.platformMutationObservation.value.requiredRead='token-list';const running=f.executePlatformHealthRead();f.resolve(list);await running;assert.equal(f.b.platformMutationObservation.value.requiredRead,'token-list');
});
test('actual routing cancels only explicit health reads, never mutations or their acknowledgement reconciliation',()=>{
 const execute=source.slice(source.indexOf('async function execute(action:'),source.indexOf('async function reviewRemoteTicket('));assert.match(execute,/definition.value.id === 'platform-ops' && action === 'run'\) \{ await executePlatformHealthRead\(\); return; \}/);assert.equal((execute.match(/executePlatformHealthRead\(/g)||[]).length,1);assert.doesNotMatch(execute,/request.controller|\.abort\(/);
 assert.match(source,/onBeforeUnmount\(cancelPlatformHealthRead\)/);assert.match(source,/cancelDiskScan\(\); cancelPlatformHealthRead\(\); clearWriteOnlyFields/);assert.match(source,/idsAccessGeneration\+\+;cancelDiskScan\(\);cancelPlatformHealthRead\(\);/);
 const footer=source.slice(source.indexOf('<template #footer>'));assert.match(footer,/v-if="definition\?\.id==='platform-ops' && platformReadRequest"[^>]*@click="cancelPlatformHealthRead"/);assert.doesNotMatch(handlers,/setInterval|setTimeout|\/revoke-token|\/remove|\/add/);
});
test('retired legacy lifecycle entry refuses before reading credentials or executing SSH',()=>{
 const entry=new URL('./test-software-routing-install-browser.mjs',import.meta.url),text=readFileSync(entry,'utf8');
 assert(text.indexOf("throw Error('旧生命周期验收入口已退役")<text.indexOf('fs.readFileSync('));
 assert(text.indexOf("throw Error('旧生命周期验收入口已退役")<text.indexOf("const backup=ssh("));
 const result=spawnSync(process.execPath,[fileURLToPath(entry)],{encoding:'utf8',timeout:5000});assert.equal(result.status,1);assert.match(result.stderr,/旧生命周期验收入口已退役/);assert.equal(result.stdout,'');
});
