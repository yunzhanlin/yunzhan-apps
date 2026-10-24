import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import ts from '../web/node_modules/typescript/lib/typescript.js';
import {ref,reactive,computed,watch,effectScope} from '../web/node_modules/vue/index.mjs';
const source=readFileSync(new URL('../web/src/RedisManager.vue',import.meta.url),'utf8').split('<script setup lang="ts">')[1].split('</script>')[0];
const ast=ts.createSourceFile('RedisManager.ts',source,ts.ScriptTarget.Latest,true,ts.ScriptKind.TS);
const statements=ast.statements.filter(n=>!ts.isImportDeclaration(n)&&!(ts.isExpressionStatement(n)&&n.expression.expression?.getText(ast)==='defineExpose'));
const js=ts.transpileModule(statements.map(n=>n.getText(ast)).join('\n'),{compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.ESNext}}).outputText;
const names=['drawer','credentialsOpen','credentialsLoading','credentials','credentialsName','showCredentials','clearCredentials'];
const id='a'.repeat(32),password='bc'.repeat(32),item={id,name:'owned Redis fixture',port:16379,status:'running',auth_mode:'acl-password-v1'};
const response=()=>({host:'127.0.0.1',port:16379,username:'app-'+id.slice(0,12),password,auth_mode:'acl-password-v1'});
const deferred=()=>{let resolve,reject;const promise=new Promise((a,b)=>{resolve=a;reject=b});return{promise,resolve,reject};};
function fixture(api=async()=>response()){
 const scope=effectScope(),calls=[],messages=[],timers=new Map(),windowEvents=new Map(),documentEvents=new Map();
 let timerID=0;
 const props=reactive({csrf:'fixture-session',access:{role:'admin',menu_ids:['databases']},installed:[],api:(...args)=>{calls.push(args);return api(...args);}});
 const b={ref,computed,watch,defineProps:()=>props,defineEmits:()=>()=>{},
  ElMessage:Object.fromEntries(['success','warning','error'].map(k=>[k,value=>messages.push([k,value])])),
  ElMessageBox:{},onBeforeUnmount(fn){b.dispose=fn;},
  setTimeout(fn,ms){assert.equal(ms,60000);timers.set(++timerID,fn);return timerID;},
  clearTimeout(id){timers.delete(id);},
  window:{addEventListener:(name,fn)=>windowEvents.set(name,fn),removeEventListener:(name,fn)=>{assert.equal(windowEvents.get(name),fn);windowEvents.delete(name);}},
  document:{hidden:false,addEventListener:(name,fn)=>documentEvents.set(name,fn),removeEventListener:(name,fn)=>{assert.equal(documentEvents.get(name),fn);documentEvents.delete(name);}}
 };
 const x=scope.run(()=>new Function('b','with(b){'+js+';return {'+names.join(',')+'};}')(b));
 x.drawer.value=true;let closed=false;
 return{x,props,calls,messages,timers,windowEvents,documentEvents,b,close(){if(!closed){closed=true;b.dispose?.();scope.stop();}}};
}
test('actual credential opener uses one CSRF-scoped POST,app-only schema and explicit60s memory lease',async()=>{
 const f=fixture();try{
  await f.x.showCredentials(item);
  assert.equal(f.calls.length,1);assert.deepEqual(f.calls[0],['/redis/instances/'+id+'/credentials','POST',{}]);
  assert(f.x.credentialsOpen.value);assert.equal(f.x.credentials.value.password,password);assert.equal(f.x.credentials.value.username,'app-'+id.slice(0,12));
  assert.equal(f.timers.size,1);assert(!f.x.credentialsLoading.value);
  const displayed=f.x.credentials.value;[...f.timers.values()][0]();
  assert.equal(displayed.password,'');assert.equal(f.x.credentials.value,null);assert(!f.x.credentialsOpen.value);assert.equal(f.timers.size,0);
 }finally{f.close();}
});
test('actual credential opener never contacts backend without database-admin grant or for an old unauthenticated instance',async()=>{
 for(const change of [
  f=>f.props.access.role='viewer',f=>f.props.access.menu_ids=['runtimes'],f=>f.props.access=null,f=>f.props.csrf='',
  f=>f.x.drawer.value=false,
 ]){
  const f=fixture(async()=>assert.fail('unauthorized credential API call'));
  try{change(f);await f.x.showCredentials(item);assert.equal(f.calls.length,0);}finally{f.close();}
 }
 const f=fixture(async()=>assert.fail('old instance migrated or secret requested'));
 try{await f.x.showCredentials({...item,auth_mode:undefined});assert.equal(f.calls.length,0);}finally{f.close();}
});
test('closing manager,replacing account,revoking grant,explicit close and unmount clear actual secret object and timer',async()=>{
 for(const change of [
  f=>f.x.drawer.value=false,f=>f.props.csrf='replacement',f=>f.props.access.menu_ids=[],
  f=>f.x.credentialsOpen.value=false,f=>f.close(),
 ]){
  const f=fixture();try{
   await f.x.showCredentials(item);const original=f.x.credentials.value;assert(original);
   change(f);assert.equal(original.password,'');assert.equal(f.x.credentials.value,null);assert.equal(f.timers.size,0);assert(!f.x.credentialsOpen.value);
  }finally{f.close();}
 }
});
test('late credential responses cannot repopulate replacement authority,closed manager or disposed UI',async()=>{
 for(const change of [f=>f.x.drawer.value=false,f=>f.props.csrf='replacement',f=>f.props.access=null,f=>f.close()]){
  const d=deferred(),f=fixture(()=>d.promise);try{
   const request=f.x.showCredentials(item);change(f);const late=response();d.resolve(late);await request;
   assert.equal(f.x.credentials.value,null);assert.equal(late.password,'');assert.equal(f.timers.size,0);
  }finally{f.close();}
 }
});
test('newer same-account credential read cannot be overwritten by older pending response',async()=>{
 const first=deferred(),second=deferred();let count=0;
 const f=fixture(()=>++count===1?first.promise:second.promise);
 try{
  const a=f.x.showCredentials(item),b=f.x.showCredentials(item);const newest=response();second.resolve(newest);await b;
  const old=response();first.resolve(old);await a;
  assert.equal(f.x.credentials.value.password,password);assert.equal(old.password,'');assert.equal(f.timers.size,1);
 }finally{f.close();}
});
test('pagehide and document hiding clear displayed credential without another API request',async()=>{
 for(const event of ['pagehide','visibilitychange']){
  const f=fixture();try{
   await f.x.showCredentials(item);const displayed=f.x.credentials.value;
   if(event==='pagehide')f.windowEvents.get(event)();else{f.b.document.hidden=true;f.documentEvents.get(event)();}
   assert.equal(displayed.password,'');assert.equal(f.x.credentials.value,null);assert.equal(f.calls.length,1);
  }finally{f.close();}
  assert.equal(f.windowEvents.size,0);assert.equal(f.documentEvents.size,0);
 }
});
test('invalid or administrative credential response is rejected without storing,password echo or retry',async()=>{
 for(const mutate of [v=>v.host='public.invalid',v=>v.port=6379,v=>v.username='panel-admin',v=>v.auth_mode='legacy',v=>v.password='z'.repeat(64)]){
  const v=response();mutate(v);const f=fixture(async()=>v);
  try{await f.x.showCredentials(item);assert.equal(f.x.credentials.value,null);assert.equal(v.password,'');assert.equal(f.calls.length,1);assert.equal(f.timers.size,0);assert(f.messages.some(([k])=>k==='error'));assert(!f.messages.some(([,m])=>String(m).includes(password)));}
  finally{f.close();}
 }
});
test('native credential UI is masked,not persisted,and normal release actually runs the new executable regression',()=>{
 const vue=readFileSync(new URL('../web/src/RedisManager.vue',import.meta.url),'utf8');
 assert(vue.includes('type="password" show-password readonly autocomplete="new-password"'));
 assert(!vue.includes('localStorage')&&!vue.includes('sessionStorage')&&!vue.includes('navigator.clipboard'));
 assert(vue.includes('旧实例 · 未认证')&&vue.includes('逻辑库不是账号隔离边界'));
 const release=readFileSync(new URL('../packaging/build-release.sh',import.meta.url),'utf8');
 assert(release.includes('node --test scripts/test-redis-credentials.mjs'));
});

