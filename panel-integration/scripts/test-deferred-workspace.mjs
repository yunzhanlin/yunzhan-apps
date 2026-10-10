import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import ts from '../web/node_modules/typescript/lib/typescript.js';
const read=p=>readFileSync(new URL('../'+p,import.meta.url),'utf8');
const compiled=p=>ts.transpileModule(read(p),{compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.ESNext}}).outputText;
const {DeferredWorkspace,WorkspaceCodeLoadError,scopeWorkspaceAPI,scopeWorkspaceOperation}=await import('data:text/javascript;base64,'+Buffer.from(compiled('web/src/deferredWorkspace.ts')).toString('base64'));
const {canOpenAppModule,canReadPath,menuPermissionIDs}=await import('data:text/javascript;base64,'+Buffer.from(compiled('web/src/menuPermissions.ts')).toString('base64'));
const deferred=()=>{let resolve,reject;const promise=new Promise((a,b)=>{resolve=a;reject=b;});return {promise,resolve,reject};};
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
