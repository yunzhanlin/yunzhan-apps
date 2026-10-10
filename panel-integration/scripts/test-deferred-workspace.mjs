import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import ts from '../web/node_modules/typescript/lib/typescript.js';
const read=p=>readFileSync(new URL('../'+p,import.meta.url),'utf8');
const compiled=p=>ts.transpileModule(read(p),{compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.ESNext}}).outputText;
const {DeferredWorkspace,WorkspaceCodeLoadError,scopeWorkspaceAPI,scopeWorkspaceOperation}=await import('data:text/javascript;base64,'+Buffer.from(compiled('web/src/deferredWorkspace.ts')).toString('base64'));
const {canOpenAppModule,canReadPath,menuPermissionIDs}=await import('data:text/javascript;base64,'+Buffer.from(compiled('web/src/menuPermissions.ts')).toString('base64'));
const {initialModuleInspection}=await import('data:text/javascript;base64,'+Buffer.from(compiled('web/src/moduleInitialInspection.ts')).toString('base64'));
const deferred=()=>{let resolve,reject;const promise=new Promise((a,b)=>{resolve=a;reject=b;});return {promise,resolve,reject};};
const initial=(id,actions=['run'],fields=null,installed=true,ready=true)=>initialModuleInspection(id,{id,actions,fields},installed,ready);
test('dedicated Apache opening cannot issue a generic inspection; existing reviewed inspections stay intact',()=>{
 for(const actions of [['run'],['run','policies'],['server-report','run']])assert.equal(initial('apache-waf',actions),undefined);
 assert.equal(initial('nfs-manager',['server-report','policies','run']),'server-report');
 assert.equal(initial('nfs-manager',['run']),undefined,'never substitute the mount report for the server report');
 for(const id of ['file-monitor','website-tamper-proof','enterprise-tamper-proof'])assert.equal(initial(id,['policies','run'],[{key:'site_id',kind:'site'}]),'policies');
 for(const id of ['files-sync','pure-ftpd'])assert.equal(initial(id,['run'],[{key:'site_id',kind:'site'}]),'run');
 for(const id of ['network-threat-detection','daily-report','load-balance','mobile-pwa','task-manager','user-manager'])assert.equal(initial(id),'run');
 for(const id of ['site-diagnosis','website-analytics','website-statistics-v2','php-code-security','disk-analysis','pm2-manager'])assert.equal(initial(id,['run'],[{key:'site_id',kind:'site'}]),undefined);
 assert.equal(initial('platform-ops'),undefined);
 assert.equal(initial('task-manager',['save','install','update','terminate']),undefined);
});
test('partial reads, wrong identities, unknown modules and malformed definitions cannot trigger an opening action',()=>{
 for(const installed of [false,undefined,null,1,'true'])assert.equal(initialModuleInspection('task-manager',{id:'task-manager',actions:['run'],fields:null},installed,true),undefined);
 for(const ready of [false,undefined,null,1,'true'])assert.equal(initialModuleInspection('task-manager',{id:'task-manager',actions:['run'],fields:null},true,ready),undefined);
 for(const id of ['unknown','__proto__','constructor','../../task-manager','','nginx-waf'])assert.equal(initial(id),undefined);
 for(const definition of [null,[],{}, {id:'daily-report',actions:['run'],fields:null},
   {id:'task-manager',actions:null,fields:null}, {id:'task-manager',actions:['run','run'],fields:null},
   {id:'task-manager',actions:['run','bad/action'],fields:null}, {id:'task-manager',actions:['run',17],fields:null},
   {id:'task-manager',actions:Array.from({length:65},(_,i)=>'a'+i),fields:null},
   ...[undefined,{},[null],[[]],[{key:'pid'}],[{key:'pid',kind:1}],
     [{key:'../pid',kind:'site'}],[{key:'pid',kind:'bad/kind'}],
     [{key:'pid',kind:'number'},{key:'pid',kind:'number'}],
     Array.from({length:65},(_,i)=>({key:'a'+i,kind:'text'}))].map(fields=>({id:'task-manager',actions:['run'],fields})),
 ])assert.equal(initialModuleInspection('task-manager',definition,true,true),undefined);
 assert.equal(initial('task-manager',['run'],[{key:'start_time',kind:'number'}]),'run');
});
test('actual manager uses the closed selector only after its complete page and dependent reads succeed',()=>{
 const manager=read('web/src/AppModuleManager.vue');
 assert.match(manager,/import \{ initialModuleInspection \} from "\.\/moduleInitialInspection"/);
 const show=manager.slice(manager.indexOf('async function show('),manager.indexOf('function selected('));
 assert.match(show,/let pageReady = false/);
 assert.equal((show.match(/pageReady = true/g)||[]).length,1);
 assert(show.indexOf('pageReady = true')>show.indexOf('restoreAnalyticsQuery('));
 assert(show.indexOf('pageReady = true')<show.indexOf('} catch (e)'));
 assert.match(show,/const inspection = initialModuleInspection\(id, definition.value, installed.value, pageReady\);\s*if \(inspection\) await execute\(inspection\);/);
 assert.equal((show.match(/await execute\(/g)||[]).length,1);
 assert.doesNotMatch(show,/execute\("(?:run|policies|server-report)"\)/);
 assert.match(manager,/<WafWorkspace v-else-if="definition.id === 'apache-waf'"[^>]+engine="apache-waf"/);
 // Keep this intentionally closed module inventory aligned with the real
 // generic definitions, not the broader permission aliases or test fixtures.
 const core=read('internal/core/app_modules.go');
 const definitions=core.slice(core.indexOf('definitions := []AppModuleDefinition{'),core.indexOf('for i := range definitions'));
 const ids=[...definitions.matchAll(/^\s*\{"([a-z0-9-]+)",/gm)].map(match=>match[1]);assert.equal(ids.length,20);
 const selector=read('web/src/moduleInitialInspection.ts');
 const declared=selector.slice(selector.indexOf('const modules = new Set(['),selector.indexOf(']);'));
 assert.deepEqual([...declared.matchAll(/"([a-z0-9-]+)"/g)].map(match=>match[1]).sort(),ids.sort());
 assert.doesNotMatch(selector,/fetch\(|localStorage|sessionStorage|setTimeout|setInterval|csrf|password|secret|cookie/);
});
test('the real compiled show function refuses automatic actions after page, site or certificate read failures',async()=>{
 const manager=read('web/src/AppModuleManager.vue');
 const source=manager.slice(manager.indexOf('async function show('),manager.indexOf('function selected('));
 const js=ts.transpileModule(source,{compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.ESNext}}).outputText;
 async function open(id,failedPath,actions=['run'],fields=null){
  const refs=Object.fromEntries(['busy','error','visible','report','definition','guidance','installed','healthy','form','sites','certificates','selectedPlanID','selectedQuarantineState','workspace','history','historyFilter','historyOffset','activeTab','localVersions'].map(key=>[key,{value:undefined}]));
  const requests=[],executed=[];
  const bindings={...refs,initialModuleInspection,canReadPath,
   props:{api:async path=>{requests.push(path);if(path===failedPath)throw new Error('retained read failure '+path);
    return path==='/app-modules/'+id ? {definition:{id,actions,fields},status:{installed:true,healthy:true},report:null,workspace:[{id:'manage'}]} : []; }},
   setReport:value=>{refs.report.value=value;},analyticsQueryContext:()=>undefined,restoreAnalyticsQuery:()=>undefined,
   execute:async action=>{executed.push(action);}};
  await new Function(...Object.keys(bindings),js+'\nreturn show;')(...Object.values(bindings))(id);
  return {requests,executed,error:refs.error.value,installed:refs.installed.value};
 }
 for(const [id,path] of [['task-manager','/app-modules/task-manager'],['task-manager','/sites'],['pure-ftpd','/certificates']]){
  const out=await open(id,path);assert.equal(out.requests.at(-1),path);assert.deepEqual(out.executed,[]);assert.match(out.error,/retained read failure/);
  if(path==='/sites'||path==='/certificates')assert.equal(out.installed,true,'partial installation state must not authorize an action');
 }
 assert.deepEqual((await open('apache-waf')).executed,[]);
 assert.deepEqual((await open('task-manager')).executed,['run']);
 assert.deepEqual((await open('pure-ftpd',undefined,['run'],[{key:'site_id',kind:'site'}])).executed,['run']);
 assert.deepEqual((await open('nfs-manager',undefined,['run','server-report'])).executed,['server-report']);
 assert.deepEqual((await open('file-monitor',undefined,['policies'],[{key:'site_id',kind:'site'}])).executed,['policies']);
});
test('constructing the opener does not request any chunk or mount a workspace',()=>{
 let calls=0;new DeferredWorkspace(async()=>{calls++;return {};});assert.equal(calls,0);
});
test('concurrent first opens share one code request and only the most recent ticket can mount',async()=>{
 const d=deferred(),code={component:'fixture'};let calls=0;
 const gate=new DeferredWorkspace(()=>{calls++;return d.promise;});
 const a=gate.begin(),old=gate.load(a),b=gate.begin(),latest=gate.load(b);
 await Promise.resolve();assert.equal(calls,1);d.resolve(code);
 assert.equal(await old,undefined);assert.equal(await latest,code);assert(!gate.current(a));assert(gate.current(b));
 assert.equal(await gate.load(gate.begin()),code);assert.equal(calls,1);
});
test('cancelling or changing accounts discards late mount intent but can reuse only code',async()=>{
 const d=deferred(),code={};let calls=0;const gate=new DeferredWorkspace(()=>{calls++;return d.promise;});
 const ticket=gate.begin(),old=gate.load(ticket);gate.reset();d.resolve(code);assert.equal(await old,undefined);
 assert.equal(await gate.load(gate.begin()),code);assert.equal(calls,1);
});
test('disposing the root refuses later requests and never mounts a late chunk',async()=>{
 const d=deferred(),gate=new DeferredWorkspace(()=>d.promise),ticket=gate.begin(),pending=gate.load(ticket);
 gate.dispose();d.resolve({});assert.equal(await pending,undefined);assert(!gate.current(ticket));assert.throws(()=>gate.begin(),/关闭/);
 assert.equal(await gate.load(ticket),undefined);
});
test('a failed module record requires a fresh document rather than an ineffective identical import',async()=>{
 let calls=0;const code={};const gate=new DeferredWorkspace(async()=>{calls++;if(calls===1)throw new Error('real loader failure fixture');return code;});
 await assert.rejects(gate.load(gate.begin()),e=>e instanceof WorkspaceCodeLoadError&&/real loader failure/.test(e.message));await Promise.resolve();assert.equal(calls,1);
 gate.reset();await assert.rejects(gate.load(gate.begin()),WorkspaceCodeLoadError);assert.equal(calls,1);
 // This is only a new in-memory loader fixture, not browser-reload proof.
 const freshDocument=new DeferredWorkspace(async()=>{calls++;return code;});
 assert.equal(await freshDocument.load(freshDocument.begin()),code);assert.equal(calls,2);
});
test('code-transfer rejection is bounded and does not mistake an API operation failure for a module error',async()=>{
 const gate=new DeferredWorkspace(async()=>{throw new Error('x'.repeat(3000));});
 await assert.rejects(gate.load(gate.begin()),e=>e instanceof WorkspaceCodeLoadError&&e.message.length===512);
 const operation=scopeWorkspaceAPI(async()=>{throw new Error('actual API failure');},()=>true);
 await assert.rejects(operation('/app-modules/files-sync'),e=>!(e instanceof WorkspaceCodeLoadError)&&e.message==='actual API failure');
});
test('refresh recovery is explicit and cannot persist or automatically replay an operation',()=>{
 const app=read('web/src/App.vue');
 const reload=app.slice(app.indexOf('function reloadAppModuleWorkspace()'),app.indexOf('async function openAppModule('));
 assert.match(reload,/if \(!appModuleReloadRequired.value \|\| !appModuleLoadError.value \|\| appModuleLoading.value\) return/);
 assert.match(reload,/window.location.reload\(\)/);assert.match(reload,/cancelAppModuleLoad\(\)/);
 assert.doesNotMatch(reload,/localStorage|sessionStorage|api\(|queueSoftwareInstall|openAppModule\(|lifecycleJob\(/);
 assert.match(app,/cause instanceof WorkspaceCodeLoadError/);
 assert.match(app,/不会自动重试已提交的任务/);assert.match(app,/刷新会清除当前页面未保存的内容/);
 assert.match(app,/v-if="appModuleLoadError && appModuleReloadRequired"[^>]+@click="reloadAppModuleWorkspace">刷新面板/);
 assert.match(app,/v-else-if="appModuleLoadError"[^>]+@click="openAppModule\(appModuleLoadTarget\)">重试打开界面/);
});
test('interactive module permissions exactly match every current Core ModuleMenu mapping',()=>{
 const source=read('internal/core/menu_permissions.go'),body=source.slice(source.indexOf('func ModuleMenu('),source.indexOf('// Exact roots'));
 const groups=[...body.matchAll(/case ([^:]+):\s*return "([a-z-]+)"/g)];assert.equal(groups.length,7);
 let count=0;
 for(const [,cases,menu] of groups)for(const quoted of cases.match(/"[a-z0-9-]+"/g)||[]){
  const id=JSON.parse(quoted);count++;assert(canOpenAppModule({role:'admin',menu_ids:[menu]},id),id);
  for(const other of menuPermissionIDs.filter(x=>x!==menu))assert(!canOpenAppModule({role:'admin',menu_ids:[other]},id),id+' '+other);
 }
 assert.equal(count,26);
 for(const id of ['unknown','__proto__','constructor','../../apache-waf',''])assert(!canOpenAppModule({role:'admin',menu_ids:[...menuPermissionIDs]},id));
 for(const access of [null,{role:'viewer',menu_ids:['sites']},{role:'operator',menu_ids:['sites']},{role:'admin',menu_ids:['sites','sites']}])assert(!canOpenAppModule(access,'website-analytics'));
 assert(!canReadPath({role:'admin',menu_ids:['sites']},'/app-modules/website-analytics'),'do not broaden background reads');
 assert(canOpenAppModule({role:'admin',menu_ids:['panel-access']},'user-manager'));
});
test('scoped requests retain the original path, method, body and idempotency key',async()=>{
 const body={fixture:'non-secret'},rows=[];const api=scopeWorkspaceAPI(async(...args)=>{rows.push(args);return {job_id:'a'.repeat(32)};},()=>true);
 assert.deepEqual(await api('/app-modules/files-sync/verify','POST',body,'original-key'),{job_id:'a'.repeat(32)});
 assert.deepEqual(rows,[['/app-modules/files-sync/verify','POST',body,'original-key']]);assert.equal(rows[0][2],body);
});
test('a stale workspace cannot issue GET, POST or installation callbacks under a new account',async()=>{
 let calls=0;const api=scopeWorkspaceAPI(async()=>{calls++;return {};},()=>false);
 for(const method of ['GET','POST'])await assert.rejects(api('/app-modules/files-sync/verify',method,{}),/上下文已改变/);
 await assert.rejects(scopeWorkspaceOperation(async()=>{calls++;return 'job';},()=>false)('files-sync'),/上下文已改变/);assert.equal(calls,0);
});
test('an account change during read rejects the result before a chained write can be sent',async()=>{
 const d=deferred();let current=true,calls=0,continued=false;
 const api=scopeWorkspaceAPI(async()=>{calls++;return d.promise;},()=>current);
 const chain=(async()=>{await api('/app-modules/files-sync');continued=true;await api('/app-modules/files-sync/verify','POST',{});})();
 current=false;d.resolve({fixture:'old-account'});await assert.rejects(chain,/未复用旧结果/);assert.equal(calls,1);assert(!continued);
});
test('a submitted write whose account changes is not declared cancelled or successful and is never replayed',async()=>{
 const d=deferred();let current=true,calls=0;const api=scopeWorkspaceAPI(async()=>{calls++;return d.promise;},()=>current);
 const submitted=api('/app-registry/files-sync/install','POST',{expected_version:'fixture'},'same-original-key');
 current=false;d.resolve({job_id:'b'.repeat(32)});await assert.rejects(submitted,/此前已提交的操作须核对原任务/);assert.equal(calls,1);
});
test('deferred operation completion is discarded after its scope changes',async()=>{
 const d=deferred();let current=true,calls=0;const op=scopeWorkspaceOperation(async()=>{calls++;return d.promise;},()=>current);
 const value=op('fixture');current=false;d.resolve('old-job');await assert.rejects(value,/上下文已改变/);assert.equal(calls,1);
});
test('all module entry points wait for code and the actual mounted ref; reset tears down the old scoped instance',()=>{
 const app=read('web/src/App.vue');assert.match(app,/import type AppModuleManager/);assert.match(app,/new DeferredWorkspace\(async \(\) => \(await import\("\.\/AppModuleManager.vue"\)\)\.default\)/);
 assert.doesNotMatch(app,/appModuleManager(?:\.value)?\?\.show|<AppModuleManager\b/);
 const open=app.slice(app.indexOf('async function openAppModule('),app.indexOf('function openSoftwareApp('));
 for(const item of ['await appModuleLoader.load(ticket)','await nextTick()','if (!appModuleManager.value)','await appModuleManager.value.show(id)','epoch === accessEpoch','session === csrf.value','canOpenAppModule','scopeWorkspaceAPI(api, scopeCurrent)','scopeWorkspaceOperation(queueSoftwareInstall, scopeCurrent)'])assert(open.includes(item),item);
 assert.match(app,/else if \(manager === "module"\) void openAppModule\(app.id\)/);assert.match(app,/openAppModule\(app.target\)/);assert.match(app,/@click="openAppModule\('user-manager'\)"/);
 assert.match(app,/accessEpoch\+\+;\s*cancelAppModuleLoad\(\);\s*appModuleComponent.value = undefined/);
 assert.match(app,/appModuleScopeDisposed = true;\s*appModuleLoader.dispose\(\)/);
 assert.match(app,/:api="appModuleAPI" :on-job="appModuleJob" :on-install="appModuleInstall"/);
 assert.match(app,/重试打开界面/);assert.match(app,/取消界面加载/);assert.match(app,/这次打开界面的操作没有提交安装、更新或配置变更/);
 assert.match(read('web/src/AppModuleManager.vue'),/if \(busy.value\) throw new Error/);
 assert.doesNotMatch(read('web/src/deferredWorkspace.ts'),/fetch\(|localStorage|sessionStorage|setTimeout|setInterval|csrf|password|secret|cookie/);
 assert.match(read('web/vite.config.ts'),/chunkSizeWarningLimit: 1200/);
 assert.match(read('packaging/build-release.sh'),/test-deferred-workspace\.mjs/);
});
