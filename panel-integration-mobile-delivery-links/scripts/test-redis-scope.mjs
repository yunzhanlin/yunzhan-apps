import test from 'node:test';import assert from 'node:assert/strict';import {readFileSync} from 'node:fs';
import ts from '../web/node_modules/typescript/lib/typescript.js';
import {ref,reactive,computed,watch,effectScope} from '../web/node_modules/vue/index.mjs';
const source=readFileSync(new URL('../web/src/RedisManager.vue',import.meta.url),'utf8').split('<script setup lang="ts">')[1].split('</script>')[0];
const ast=ts.createSourceFile('RedisManager.ts',source,ts.ScriptTarget.Latest,true,ts.ScriptKind.TS);
const statements=ast.statements.filter(n=>!ts.isImportDeclaration(n)&&!(ts.isExpressionStatement(n)&&n.expression.expression?.getText(ast)==='defineExpose'));
const js=ts.transpileModule(statements.map(n=>n.getText(ast)).join('\n'),{compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.ESNext}}).outputText;
const names=['drawer','keysOpen','keysInstance','keysDB','keysList','keyInfo','keyValue','keyDraft','keyEditing','keyHashField','keyHashValue','keyHashDraft','keyHashNewField','keyHashNewValue','keyValueLoading','keyValueSaving','keyHashSaving','logs','logsOpen','instances','setKeyTTL','removeKey','removeHashField','loadKeyValue','showLogs','refresh','saveKeyValue','saveHashField','remove','showKeyInfo','addHashField'];
const deferred=()=>{let resolve,reject;const promise=new Promise((a,b)=>{resolve=a;reject=b});return{promise,resolve,reject};};
function fixture(api=async()=>({instances:[]}),prompt=async()=>({value:'0'})){
 const scope=effectScope(),calls=[],messages=[],emits=[],props=reactive({csrf:'fixture-original-session',access:{role:'admin',menu_ids:['databases','runtimes']},installed:[],api:(...args)=>{calls.push(args);return api(...args);}}),b={ref,computed,watch,defineProps:()=>props,defineEmits:()=>value=>emits.push(value),ElMessage:Object.fromEntries(['success','warning','error'].map(k=>[k,v=>messages.push([k,v])])),ElMessageBox:{prompt},onBeforeUnmount(fn){b.dispose=fn;}};
 const x=scope.run(()=>new Function('b','with(b){'+js+';return {'+names.join(',')+'};}')(b));
 x.drawer.value=true;x.keysInstance.value={id:'a'.repeat(32),name:'fixture-instance',status:'running'};x.keysDB.value=0;x.keysOpen.value=true;x.keyInfo.value={db:0,name:'fixture-key',kind:'string',ttl_seconds:60,size:6};
 return{x,props,calls,messages,emits,close(){b.dispose?.();scope.stop();}};
}
test('actual TTL prompt cannot submit after closing keys, changing database, replacing account or unmount',async()=>{
 for(const change of [f=>f.x.keysOpen.value=false,f=>f.x.keysDB.value=1,f=>f.props.csrf='replacement-session',f=>f.close()]){
  const d=deferred(),f=fixture(async()=>assert.fail('obsolete confirmation submitted'),()=>d.promise);try{const pending=f.x.setKeyTTL();change(f);d.resolve({value:'120'});await pending;assert.equal(f.calls.length,0);}finally{f.close();}
 }
});
test('actual delete-key and delete-field confirmations cannot escape the original key scope',async()=>{
 for(const method of ['removeKey','removeHashField']){const d=deferred(),f=fixture(async()=>assert.fail('obsolete deletion submitted'),()=>d.promise);try{
  f.x.keyInfo.value={db:0,name:'fixture-key',kind:'hash',ttl_seconds:60,size:1};f.x.keyHashField.value='fixture-field';f.x.keyHashValue.value='original';
  const pending=f.x[method]();f.x.keysDB.value=1;d.resolve({value:method==='removeKey'?'fixture-key':'fixture-field'});await pending;assert.equal(f.calls.length,0);
 }finally{f.close();}}
});
test('closing actual manager clears displayed private values and drafts; late value and log reads cannot repopulate',async()=>{
 for(const method of ['loadKeyValue','showLogs']){const d=deferred(),f=fixture(()=>d.promise);try{
  f.x.keyValue.value='displayed';f.x.keyDraft.value='draft';f.x.keyHashDraft.value='hash-draft';f.x.keyHashNewValue.value='new-field-value';f.x.logs.value='private-log';
  const pending=method==='showLogs'?f.x.showLogs(f.x.keysInstance.value):f.x.loadKeyValue();f.x.drawer.value=false;
  d.resolve(method==='showLogs'?{content:'late-private-log'}:{value:'late-private-value'});await pending;
  assert.equal(f.x.keyValue.value,null);assert.equal(f.x.keyDraft.value,'');assert.equal(f.x.keyHashDraft.value,'');assert.equal(f.x.keyHashNewValue.value,'');assert.equal(f.x.logs.value,'');assert(!f.x.logsOpen.value);assert(!f.x.keysOpen.value);
 }finally{f.close();}}
});
test('old account list response cannot fill replacement account instances',async()=>{
 const d=deferred(),f=fixture(()=>d.promise);try{const pending=f.x.refresh();f.props.csrf='replacement-session';d.resolve({instances:[{id:'old-private-instance'}]});await pending;assert.deepEqual(f.x.instances.value,[]);}finally{f.close();}
});
test('same-scope text save retains the existing CAS body and never replays',async()=>{
 const f=fixture(async()=>({}));try{f.x.keyValue.value='old';f.x.keyDraft.value='new';await f.x.saveKeyValue();assert.equal(f.calls.length,1);assert.equal(f.calls[0][1],'PUT');assert.deepEqual(f.calls[0][2],{db:0,name:'fixture-key',old_value:'old',value:'new'});assert.equal(f.x.keyValue.value,'new');}finally{f.close();}
});
test('late submitted text or hash save cannot clear a newer busy flag or report success after scope change',async()=>{
 for(const method of ['saveKeyValue','saveHashField']){const d=deferred(),f=fixture(()=>d.promise);try{
  f.x.keyValue.value='old';f.x.keyDraft.value='new';f.x.keyInfo.value={db:0,name:'fixture-key',kind:method==='saveHashField'?'hash':'string',ttl_seconds:60,size:1};f.x.keyHashField.value='field';f.x.keyHashValue.value='old';f.x.keyHashDraft.value='new';
  const pending=f.x[method]();assert.equal(f.calls.length,1);f.x.keysDB.value=1;f.x.keyValueSaving.value=true;f.x.keyHashSaving.value=true;d.resolve({});await pending;
  assert(f.x.keyValueSaving.value&&f.x.keyHashSaving.value);assert.equal(f.x.keyValue.value,null);assert(!f.messages.some(([k])=>k==='success'));assert.equal(f.calls.length,1);
 }finally{f.close();}}
});
test('instance deletion prompt never submits under a replacement account or closed manager',async()=>{
 for(const change of [f=>f.props.csrf='replacement-session',f=>f.x.drawer.value=false,f=>f.props.access=null]){const d=deferred(),f=fixture(async()=>assert.fail('obsolete instance delete'),()=>d.promise);try{const pending=f.x.remove(f.x.keysInstance.value);change(f);d.resolve({value:'fixture-instance'});await pending;assert.equal(f.calls.length,0);}finally{f.close();}}
});
test('switching actual selected key invalidates the earlier confirmation without relying on server rejection',async()=>{
 const d=deferred(),f=fixture(async()=>({db:0,name:'another-key',kind:'string'}),()=>d.promise);try{const pending=f.x.setKeyTTL();await f.x.showKeyInfo('another-key');d.resolve({value:'120'});await pending;assert.equal(f.calls.length,1);assert(!f.calls.some(c=>c[1]==='PUT'));}finally{f.close();}
});
test('same-scope TTL save and hash addition retain normal completion after their own detail refresh',async()=>{
 for(const method of ['setKeyTTL','addHashField']){const f=fixture(async(url,verb)=>{
  if(url==='/redis/instances')return{instances:[]};if(url.includes('/keys/info'))return{db:0,name:'fixture-key',kind:method==='addHashField'?'hash':'string',ttl_seconds:120,size:1};
  if(url.includes('/keys/preview'))return{db:0,name:'fixture-key',kind:'hash',total:1,items:[{name:'new-field',value:'new-value'}]};return{};
 },async()=>({value:'120'}));try{f.x.keyInfo.value={db:0,name:'fixture-key',kind:method==='addHashField'?'hash':'string',ttl_seconds:60,size:1};f.x.keyHashNewField.value='new-field';f.x.keyHashNewValue.value='new-value';await f.x[method]();assert(f.messages.some(([k])=>k==='success'));assert.equal(f.calls.filter(c=>c[1]==='PUT'||c[1]==='POST').length,1);}finally{f.close();}}
});
test('both actual parent entry points supply session and access authority, and normal release runs this gate',()=>{
 const app=readFileSync(new URL('../web/src/App.vue',import.meta.url),'utf8'),blocks=[...app.matchAll(/<RedisManager\b[^>]*\/>/g)].map(m=>m[0]);assert.equal(blocks.length,2);
 for(const block of blocks){assert(block.includes(':csrf="csrf"'));assert(block.includes(':access="accessPlan"'));}
 const release=readFileSync(new URL('../packaging/build-release.sh',import.meta.url),'utf8');assert(release.includes('node --test scripts/test-redis-scope.mjs'));
});
