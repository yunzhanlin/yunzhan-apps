import test from 'node:test';import assert from 'node:assert/strict';import {readFileSync} from 'node:fs';import ts from '../web/node_modules/typescript/lib/typescript.js';
import {ref,reactive,computed,watch,effectScope} from '../web/node_modules/vue/index.mjs';
const permissionSource=readFileSync(new URL('../web/src/menuPermissions.ts',import.meta.url),'utf8');
const permissionJS=ts.transpileModule(permissionSource,{compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.CommonJS}}).outputText;
const permissionExports={};new Function('exports',permissionJS)(permissionExports);const {canOpenAppModule}=permissionExports;
const bindingSource=readFileSync(new URL('../web/src/dockerProjectSiteBinding.ts',import.meta.url),'utf8');
const bindingExports={};new Function('exports',ts.transpileModule(bindingSource,{compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.CommonJS}}).outputText)(bindingExports);
const {canBindDockerProjectSite}=bindingExports;
const source=readFileSync(new URL('../web/src/DockerManager.vue',import.meta.url),'utf8').split('<script setup lang="ts">')[1].split('</script>')[0];
const ast=ts.createSourceFile('DockerManager.ts',source,ts.ScriptTarget.Latest,true,ts.ScriptKind.TS);
const statements=ast.statements.filter(n=>!ts.isImportDeclaration(n)&&!(ts.isExpressionStatement(n)&&n.expression.expression?.getText(ast)==='defineExpose'));
const js=ts.transpileModule(statements.map(n=>n.getText(ast)).join('\n'),{compilerOptions:{target:ts.ScriptTarget.ES2022}}).outputText;
const job='a'.repeat(32),site='b'.repeat(32);
function fixture(response){
 let clock=0;const calls=[],messages=[],saved=new Map(),scope=effectScope();
 const props=reactive({csrf:'fixture-original-session',access:{role:'admin',menu_ids:['system-tools']},async api(...args){calls.push(args);return args[1]==='POST'?{job_id:job}:response(calls.filter(x=>x[1]!=='POST').length);}});
 const env={ref,computed,watch,canOpenAppModule,defineProps:()=>props,randomId:()=> 'c'.repeat(32),formatPanelDateTime:()=>'',Date:{now:()=>clock},setTimeout(fn,ms){clock+=ms;queueMicrotask(fn);},sessionStorage:{getItem:k=>saved.get(k)||null,setItem:(k,v)=>saved.set(k,v),removeItem:k=>saved.delete(k)},ElMessage:Object.fromEntries(['success','error'].map(k=>[k,v=>messages.push([k,v])])),ElMessageBox:{},onBeforeUnmount(){}};
 const b=scope.run(()=>new Function('b','with(b){'+js+';return {visible,bindingProject,bindingForm,bindingOpen,busy,bindProjectSite};}')(env));
 b.visible.value=true;b.bindingProject.value={id:'d'.repeat(32)};b.bindingForm.value={name:'binding fixture',slug:'binding-fixture',domain:'fixture.example'};b.bindingOpen.value=true;
 return{b,calls,messages,saved,run:async()=>{try{return await b.bindProjectSite();}finally{scope.stop();}}};
}
test('actual Docker website binding recognizes the Core succeeded job and clears only its retained request',async()=>{
 const f=fixture(()=>({id:job,site_id:site,kind:'create_site',state:'succeeded',error:''}));await f.run();assert(f.messages.some(([kind])=>kind==='success'));assert.equal(f.b.bindingOpen.value,false);assert.equal(f.saved.size,0);assert.equal(f.calls.filter(x=>x[1]==='POST').length,1);
 const core=readFileSync(new URL('../internal/core/store.go',import.meta.url),'utf8');assert(core.includes('state := "succeeded"'));
});
test('actual Docker binding never labels a still-running deadline as completed or discards the original request',async()=>{
 const f=fixture(()=>({id:job,site_id:site,kind:'create_site',state:'running',error:''}));await f.run();assert(!f.messages.some(([kind])=>kind==='success'));assert(f.messages.some(([kind])=>kind==='error'));assert.equal(f.b.bindingOpen.value,true);assert.equal(f.saved.size,1);assert.equal(f.calls.filter(x=>x[1]==='POST').length,1);assert(f.calls.length<=202);
});
test('actual failed or needs-attention Docker binding retains its original request without automatic submission',async()=>{
 for(const state of ['failed','needs_attention']){const f=fixture(()=>({id:job,site_id:site,kind:'create_site',state,error:'original failure retained'}));await f.run();assert(!f.messages.some(([kind])=>kind==='success'));assert(f.messages.some(([kind,text])=>kind==='error'&&text.includes('original failure retained')));assert.equal(f.saved.size,1);assert.equal(f.calls.length,2);}
});
test('actual Docker binding refuses foreign, incomplete and unknown job responses rather than adopting success',async()=>{
 for(const change of [{id:'e'.repeat(32)},{kind:'delete_site'},{site_id:''},{state:'unknown'},{id:undefined}]){const f=fixture(()=>({id:job,site_id:site,kind:'create_site',state:'succeeded',error:'',...change}));await f.run();assert(!f.messages.some(([kind])=>kind==='success'));assert(f.messages.some(([kind,text])=>kind==='error'&&/身份|状态/.test(text)));assert.equal(f.saved.size,1);assert.equal(f.calls.filter(x=>x[1]==='POST').length,1);}
});
test('a successful old Docker binding cannot delete a different pending browser request',async()=>{
 const f=fixture(()=>{f.saved.set('panel-pending-app-site','different original pending request');return{id:job,site_id:site,kind:'create_site',state:'succeeded',error:''};});await f.run();assert(f.messages.some(([kind])=>kind==='success'));assert.equal(f.saved.get('panel-pending-app-site'),'different original pending request');assert.equal(f.calls.filter(x=>x[1]==='POST').length,1);
});
test('actual template health predicate enables only recognized fully healthy unbound website projects',()=>{
 for(const template_id of ['nginx-static','wordpress-blog','openlitespeed','php-legacy-52','php-legacy-81']){
  assert(canBindDockerProjectSite({template_id,state:'running',services:1,running:1,healthy:1,host_port:23862}));
 }
});
test('actual template health predicate refuses old no-health containers, partial counts, arbitrary IDs and foreign ports',()=>{
 const p={template_id:'nginx-static',state:'running',services:1,running:1,healthy:1,host_port:23862};
 for(const change of [{healthy:undefined},{healthy:0},{healthy:2},{healthy:'1'},{running:0},{services:0},{services:-1},{services:NaN},{host_port:1023},{host_port:65536},{host_port:'23862'},{state:'unknown'},{state:'stopped'},{site_name:'existing site'},{template_id:'php-legacy-99'},{template_id:'redis-cache'},{template_id:''},{template_id:undefined}]){
  assert.equal(canBindDockerProjectSite({...p,...change}),false,JSON.stringify(change));
 }
});
test('actual Vue binding affordance uses the health predicate rather than only a running label',()=>{
 const vue=readFileSync(new URL('../web/src/DockerManager.vue',import.meta.url),'utf8');
 assert(vue.includes('v-if="canBindDockerProjectSite(item)"'));assert(vue.includes('健康检查通过'));
 assert(!vue.includes("item.template_id?.startsWith('php-legacy-')"));
});
