import test from 'node:test';import assert from 'node:assert/strict';import {readFileSync} from 'node:fs';
import ts from '../web/node_modules/typescript/lib/typescript.js';import {ref,reactive,shallowRef,watch,effectScope} from '../web/node_modules/vue/index.mjs';
const source=readFileSync(new URL('../web/src/AppModuleManager.vue',import.meta.url),'utf8').split('<script setup lang="ts">')[1].split('</script>')[0],ast=ts.createSourceFile('AppModuleManager.ts',source,ts.ScriptTarget.Latest,true,ts.ScriptKind.TS);
const functions=new Set(['checkVersions','cancelVersionRead','versionReadMatches']);
const statements=ast.statements.filter(n=>ts.isFunctionDeclaration(n)&&functions.has(n.name?.text)||ts.isVariableStatement(n)&&n.declarationList.declarations.some(d=>d.name.getText(ast)==='versionReadRequest')||ts.isExpressionStatement(n)&&/^(watch|onBeforeUnmount)\(/.test(n.getText(ast))&&n.getText(ast).includes('cancelVersionRead'));
const js=ts.transpileModule(statements.map(n=>n.getText(ast)).join('\n'),{compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.ESNext}}).outputText;
const deferred=()=>{let resolve,reject;const promise=new Promise((a,b)=>{resolve=a;reject=b;});return{promise,resolve,reject};};
function fixture(api){
 const calls=[],scope=effectScope(),props=reactive({access:{user_id:'a'.repeat(32),role:'admin'},api:(...a)=>{calls.push(a);return api(...a);}}),b={ref,shallowRef,watch,props,visible:ref(true),definition:ref({id:'daily-report'}),busy:ref(false),error:ref(''),localVersions:shallowRef(),onBeforeUnmount(fn){b.dispose=fn;}};
 const run=scope.run(()=>new Function('b','with(b){'+js+';return checkVersions;}')(b));return{b,props,calls,run,close(){b.dispose?.();scope.stop();}};
}
test('actual module version reply cannot populate a closed or replacement application/account',async()=>{
 for(const change of [f=>f.b.visible.value=false,f=>f.b.definition.value={id:'file-monitor'},f=>f.props.access={user_id:'b'.repeat(32),role:'admin'},f=>f.close()]){
  const d=deferred(),f=fixture(()=>d.promise);try{const pending=f.run();change(f);d.resolve({source:{stale:false},status:[{id:'old-account-module'}]});await pending;assert.equal(f.b.localVersions.value,undefined);assert.equal(f.b.busy.value,false);}finally{f.close();}
 }
});
test('actual canceled version read cannot clear a newer request busy state or replace its result',async()=>{
 const first=deferred(),second=deferred();let n=0;const f=fixture(()=>++n===1?first.promise:second.promise);try{
  const old=f.run();f.b.visible.value=false;f.b.definition.value={id:'file-monitor'};f.b.visible.value=true;
  const newer=f.run();assert.equal(f.calls.length,2);assert(f.b.busy.value);first.resolve({old:true});await old;assert(f.b.busy.value);assert.equal(f.b.localVersions.value,undefined);
  const actual={catalog:{apps:[]},status:[],source:{stale:false}};second.resolve(actual);await newer;assert.deepEqual(f.b.localVersions.value,actual);assert.equal(f.b.busy.value,false);
 }finally{f.close();}
});
test('actual late version error cannot overwrite replacement-account status',async()=>{
 const d=deferred(),f=fixture(()=>d.promise);try{const pending=f.run();f.props.access=null;f.b.error.value='current account has no access';d.reject(new Error('obsolete private failure'));await pending;assert.equal(f.b.error.value,'current account has no access');assert.equal(f.b.localVersions.value,undefined);}finally{f.close();}
});
test('same-scope normal version inspection completes once; hidden or already busy manager sends no read',async()=>{
 const actual={catalog:{apps:[]},status:[],source:{stale:false}},f=fixture(async()=>actual);try{
  await f.run();assert.deepEqual(f.b.localVersions.value,actual);assert.equal(f.calls.length,1);assert.equal(f.calls[0][0],'/app-registry?refresh=1');assert.equal(f.b.busy.value,false);
  f.b.busy.value=true;await f.run();assert.equal(f.calls.length,1);f.b.busy.value=false;f.b.visible.value=false;await f.run();assert.equal(f.calls.length,1);
 }finally{f.close();}
});
test('actual version read carries an AbortSignal and synchronously cancels on scope loss',async()=>{
 const d=deferred(),f=fixture(()=>d.promise);try{const pending=f.run();const signal=f.calls[0][4];assert(signal instanceof AbortSignal);assert(!signal.aborted);f.b.visible.value=false;assert(signal.aborted);d.resolve({});await pending;assert.equal(f.b.localVersions.value,undefined);}finally{f.close();}
});
