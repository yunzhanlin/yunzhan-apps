import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import ts from '../web/node_modules/typescript/lib/typescript.js';
import {wafApplyTaskOutcome} from '../web/src/wafApplyTask.ts';
const read=name=>readFileSync(new URL('../'+name,import.meta.url),'utf8');
const transpile=source=>ts.transpileModule(source,{compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.ESNext}}).outputText;
const {softwareInstallState,uniqueSoftwareStatus}=await import('data:text/javascript;base64,'+Buffer.from(transpile(read('web/src/softwareState.ts'))).toString('base64'));
const known={id:'task-manager',installed:false,enabled:false,healthy:false};
const bad=[undefined,null,{...known,state_unknown:true},{...known,installed:true,healthy:true,state_unknown:true},{...known,state_unknown:'false'},{...known,installed:'false'},{...known,enabled:undefined},{...known,healthy:true}];
const appSource=read('web/src/App.vue'),securitySource=read('web/src/SecurityAppManager.vue');
const wafSource=read('web/src/WafWorkspace.vue');
const actual=(source,start,end,bindings,name)=>{
 const a=source.indexOf(start),b=source.indexOf(end,a);assert(a>=0&&b>a);
 return new Function('bindings','with(bindings){'+transpile(source.slice(a,b))+';return '+name+';}')(bindings);
};
test('missing, untrusted and malformed records stay unknown; known absence and legacy flags stay distinct',()=>{
 for(const row of bad)assert.equal(softwareInstallState(row),'unknown');
 assert.equal(softwareInstallState(known),'absent');
 assert.equal(softwareInstallState({...known,state_unknown:false}),'absent');
 assert.equal(softwareInstallState({...known,installed:true}),'installed');
 const trusted={...known,installed:true,healthy:true};
 assert.equal(uniqueSoftwareStatus([],known.id),undefined);
 assert.equal(uniqueSoftwareStatus([trusted,trusted],known.id),undefined);
 assert.equal(uniqueSoftwareStatus([trusted,{...known,id:'other'}],known.id),trusted);
 assert.equal(softwareInstallState(uniqueSoftwareStatus([trusted,{...trusted,state_unknown:true}],known.id)),'unknown');
});
test('actual fallback filter does not classify unknown or duplicate status as installed or installable',()=>{
 for(const rows of [[],[{...known,state_unknown:true}],[{...known,installed:true,healthy:true,state_unknown:true}],[known,known]]){
  const softwareApps={value:{catalog:[{id:known.id,name:'任务管理器',family:'module',category:'tools',description:'',capabilities:[]}],status:rows}};
  const bindings={computed:fn=>fn(),appRegistry:{value:{catalog:{apps:[]}}},storeSearch:{value:''},storeCategory:{value:'all'},storeStatus:{value:'all'},storeSort:{value:'name'},normalizeStoreSearch:s=>s,softwareApps,softwareStatus:id=>uniqueSoftwareStatus(softwareApps.value.status,id),softwareInstallState,softwareState:id=>softwareInstallState(uniqueSoftwareStatus(softwareApps.value.status,id))};
  const filter=()=>actual(appSource,'const filteredSoftwareApps = computed(','const registryStatus =',bindings,'filteredSoftwareApps');
  assert.equal(filter().length,1);
  for(const selection of ['installed','installable']){bindings.storeStatus.value=selection;assert.equal(filter().length,0);}
 }
});
test('actual shared install dispatch rejects unknown before offline or signed registry POST',async()=>{
 for(const row of bad){
  let requests=0;
  const bindings={softwareApps:{value:{catalog:[{id:known.id,family:'module'}]}},softwareManagerKind:()=> 'module',softwareState:()=>softwareInstallState(row),api:()=>{requests++;throw Error('unexpected POST');}};
  const queue=actual(appSource,'async function queueSoftwareInstall(','const filteredSoftwareApps =',bindings,'queueSoftwareInstall');
  await assert.rejects(queue(known.id,{}),/安装状态尚未核对/);assert.equal(requests,0);
 }
});
test('actual unknown install entry only opens read-only manager; security actions cannot confirm or dispatch',async()=>{
 let opened=0,warnings=0;
 const bindings={softwareState:()=> 'unknown',ElMessage:{warning:()=>warnings++},openSoftwareApp:()=>opened++};
 const entry=actual(appSource,'function installSoftwareApp(','async function queueSoftwareInstall(',bindings,'installSoftwareApp');
 entry({id:known.id});assert.equal(opened,1);assert.equal(warnings,1);
 for(const action of ['install','configure','uninstall']){
  const scope={selected:{value:{id:'system-hardening'}},isSecuritySoftware:()=>true,busy:{value:false},stateKnown:{value:false},ElMessage:{warning:()=>warnings++},ElMessageBox:{confirm:()=>assert.fail('unknown confirmation')},props:{onInstall:()=>assert.fail('unknown install'),api:()=>assert.fail('unknown action')}};
  await actual(securitySource,'async function queue(','async function install(',scope,'queue')(action);assert.equal(scope.busy.value,false);
 }
 for(const row of bad){
  let shown=0;
  const scope={isSecuritySoftware:()=>true,show:()=>shown++,softwareInstallState,ElMessageBox:{confirm:()=>assert.fail('unknown confirmation')},queue:()=>assert.fail('unknown queue')};
  await actual(securitySource,'async function install(','defineExpose(',scope,'install')({id:'system-hardening'},row);assert.equal(shown,1);
 }
});
test('store and security dialog expose unknown separately and keep destructive controls disabled',()=>{
 assert(appSource.includes("softwareState(app.id) === 'unknown' ? '状态待核对'"));
 assert(appSource.includes("softwareState(app.id) === 'unknown' ? '核对状态'"));
 assert(appSource.includes('uniqueSoftwareStatus(softwareApps.value.status, id)'));
 assert(securitySource.includes('不能据此认定未安装'));
 assert(securitySource.includes(':disabled="!stateKnown || busy"'));
 assert(securitySource.includes('v-if="installed" type="danger"'));
});
test('actual WAF config load refuses unknown health and saved data without starting other reads or dropping original ticket',async()=>{
 for(const row of bad){
  let reads=0;
  const ticket={job:'a'.repeat(32),key:'b'.repeat(32),kind:'software_configure',settings:{original:true}};
  const bindings={engine:'nginx-waf',status:{value:{...known,installed:true,healthy:true}},implementation:{value:''},cfg:{value:{old:true}},applied:{value:{old:true}},defaults:{value:{}},saved:{value:'old green'},error:{value:''},pendingApply:{value:ticket},endpoint:part=>'/software/nginx-waf/'+part,clone:v=>structuredClone(v),props:{api:async(path,method)=>{assert.equal(path,'/software/nginx-waf/config');assert.equal(method,undefined);reads++;return{status:row,settings:{untrusted:true},defaults:{untrusted:true},implementation_version:'fixture'};}}};
  bindings.installState={get value(){return softwareInstallState(bindings.status.value);}};
  const load=actual(wafSource,'async function loadConfig()','function reportURL(',bindings,'loadConfig');
  assert.equal(await load(),false);assert.equal(reads,1);assert.equal(bindings.cfg.value,undefined);assert.equal(bindings.applied.value,undefined);assert.equal(bindings.saved.value,'');assert.equal(bindings.pendingApply.value,ticket);assert.match(bindings.error.value,/不能据此认定未安装/);
 }
});
test('actual WAF apply preview and engine build are guarded before any POST when install state is unknown',async()=>{
 for(const [name,start,end] of [['apply','async function apply()','function discard()'],['validate','async function validate()','async function showPreview('],['buildEngine','async function buildEngine()','async function stopEngine(']]){
  const bindings={disposed:false,cfg:{value:{}},busy:{value:false},installState:{value:'unknown'},error:{value:''},props:{api:()=>assert.fail('unknown WAF POST'),onInstall:()=>assert.fail('unknown WAF install')}};
  const fn=actual(wafSource,start,end,bindings,name);
  if(name==='validate')await assert.rejects(fn(),/安装状态尚未核对/);else await fn();
  assert.equal(bindings.busy.value,false);
 }
});
test('actual failed WAF config read invalidates current health and green statement without losing original ticket',async()=>{
 const ticket={job:'a'.repeat(32)},bindings={status:{value:{...known,installed:true,healthy:true}},saved:{value:'old green'},pendingApply:{value:ticket},endpoint:()=>'/software/nginx-waf/config',props:{api:async()=>{throw Error('actual config read unavailable');}}};
 await assert.rejects(actual(wafSource,'async function loadConfig()','function reportURL(',bindings,'loadConfig')(),/config read unavailable/);
 assert.equal(softwareInstallState(bindings.status.value),'unknown');assert.equal(bindings.saved.value,'');assert.equal(bindings.pendingApply.value,ticket);
});
test('actual unknown WAF original-task recheck reads once and retains exact ticket without preview POST retry or green result',async()=>{
 for(const state of ['running','succeeded','failed']){
  const engine='nginx-waf',ticket={job:'a'.repeat(32),key:'b'.repeat(32),kind:'software_configure',settings:{original:true}};
  let reads=0;
  const bindings={disposed:false,busy:{value:false},saved:{value:'old green'},error:{value:''},pendingApply:{value:ticket},installState:{value:'unknown'},engine,endpoint:part=>'/software/'+engine+'/'+part,wafApplyTaskOutcome,props:{api:async(path,method,body,key)=>{assert.equal(path,'/software/nginx-waf/jobs/'+ticket.job);assert.equal(method,undefined);assert.equal(body,undefined);assert.equal(key,undefined);reads++;return{id:ticket.job,target_id:engine,kind:ticket.kind,state,error:state==='failed'?'actual failure':''};}}};
  await actual(wafSource,'async function recheckUnknownOriginal()','async function apply()',bindings,'recheckUnknownOriginal')();
  assert.equal(reads,1);assert.equal(bindings.pendingApply.value,ticket);assert.equal(bindings.saved.value,'');assert.equal(bindings.busy.value,false);assert.match(bindings.error.value,/原请求保留/);
 }
 assert(wafSource.includes("<template v-if=\"cfg && installState !== 'unknown'\">"));
 assert(wafSource.includes('只读核对原任务'));
 assert(wafSource.includes("v-if=\"installState === 'installed' && status && !status.healthy\""));
});
