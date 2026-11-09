import test from'node:test';import assert from'node:assert/strict';import{readFileSync}from'node:fs';import{webcrypto}from'node:crypto';import ts from'../web/node_modules/typescript/lib/typescript.js';import{ref,computed,watch,reactive,effectScope,nextTick}from'../web/node_modules/vue/index.mjs';
const helperSource=readFileSync(new URL('../web/src/memcachedUnix.ts',import.meta.url),'utf8'),helper={};
new Function('exports',ts.transpileModule(helperSource,{compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.CommonJS}}).outputText)(helper);
const vue=readFileSync(new URL('../web/src/MemcachedUnixManager.vue',import.meta.url),'utf8'),body=vue.split('<script setup lang="ts">')[1].split('</script>')[0],ast=ts.createSourceFile('manager.ts',body,ts.ScriptTarget.Latest,true,ts.ScriptKind.TS);
const js=ts.transpileModule(ast.statements.filter(n=>!ts.isImportDeclaration(n)&&!(ts.isExpressionStatement(n)&&n.expression.expression?.getText(ast)==='defineExpose')).map(n=>n.getText(ast)).join('\n'),{compilerOptions:{target:ts.ScriptTarget.ES2022}}).outputText;
const actor='a'.repeat(32),project='b'.repeat(32),other='c'.repeat(32),runtime='d'.repeat(64);
const app={id:'memcached',name:'Memcached',version:'1.6.45-compat4',sha256:'e'.repeat(64),stage:'ready'};
function descriptor(){return{format:1,project_id:project,name:'private cache',site_id:'',version:app.version,state:'running',state_known:true,healthy:true,socket_path:'/var/lib/panel-executor/memcached-sockets/'+project+'/cache.sock',cache_mb:128,memory_limit_mb:192,item_limit_mb:4,editor_limit_bytes:48*1024,network_mode:'none',runtime_sha256:runtime};}
function fixture(change=()=>undefined,confirm=()=>Promise.resolve(),prompt=()=>Promise.resolve({value:''})){
 const calls=[],messages=[],emitted=[],scope=effectScope();
 const props=reactive({actor,fullAdmin:true,sites:[],async api(...args){
  calls.push(args);const modified=await change(args);if(modified!==undefined)return modified;
  const[path,method,input]=args;
  if(path==='/docker/projects')return{projects:[{id:project,name:'own cache',template_id:'memcached-cache',template_profile:'memcached-unix-v1'},{id:other,name:'old TCP',template_id:'memcached-cache'}]};
  if(path==='/app-registry/memcached/controls')return{records:[],truncated:false};
  if(path.endsWith('/workspace'))return descriptor();
  if(path.endsWith('/controls')&&method==='POST'){
   const id=args[3];return{operation:{format:1,request_id:id,project_id:project,actor_id:actor,input},state:'completed',result:{format:1,request_id:id,project_id:project,operation_sha256:'f'.repeat(64),state:'completed',final_state:input.action==='stop'?'stopped':'running',runtime_sha256:'9'.repeat(64)}};
  }
  throw new Error('unexpected fixture request '+path);
 }});
 const env={...helper,ref,computed,watch,onMounted:()=>{},onUnmounted:()=>{},defineProps:()=>props,defineEmits:()=> (...args)=>emitted.push(args),ElMessage:Object.fromEntries(['success','error','warning','info'].map(k=>[k,m=>messages.push([k,m])])),ElMessageBox:{confirm,prompt},crypto:webcrypto};
 const names=['visible','busy','reading','error','projects','selected','workspace','history','legacyCount','keyText','keyMode','valueText','valueMode','cas','ttl','flags','valueFound','application','installJob','installStatus','open','load','cache','control','observe','previewReview','commitReview','reviewRow','reviewView','install','checkInstallation','clearCache','closeState'];
 let manager;scope.run(()=>{manager=new Function(...Object.keys(env),js+'\nreturn {'+names.join(',')+'};')(...Object.values(env));});
 return{...manager,props,calls,messages,emitted,dispose:()=>scope.stop()};
}
test('Socket descriptor is not a Docker name, TCP route or claimed health bit',()=>{
 assert(helper.validMemcachedWorkspace(descriptor(),project));
 for(const patch of[{project_id:other},{socket_path:'/tmp/fake.sock'},{state:'running',healthy:false},{memory_limit_mb:0},{network_mode:'host'},{state_known:false},{runtime_sha256:''},{version:'1.6.45-compat2'}])assert(!helper.validMemcachedWorkspace({...descriptor(),...patch},project));
});
test('canonical binary encoding preserves bytes and refuses truncation or invalid UTF-8',()=>{
 const bytes=Uint8Array.from([0,13,10,255,128,65]),base=helper.bytesToMemcachedBase64(bytes);
 assert.deepEqual(helper.memcachedBase64Bytes(base,250),bytes);
 assert.equal(helper.memcachedValueText(base,'base64'),base);
 assert.throws(()=>helper.memcachedValueText(base,'utf8'));
 assert.throws(()=>helper.memcachedBase64Bytes('Zh==',250));
 assert.throws(()=>helper.memcachedInputBytes('汉'.repeat(20000),'utf8',48*1024));
 assert.equal(helper.memcachedBase64Bytes(helper.memcachedInputBytes('汉语\x00\r\n','utf8',250),250).length,9);
});
test('actual manager reads genuine descriptor and separates old TCP projects without mutation',async()=>{
 const f=fixture();try{await f.open(app);assert.equal(f.projects.value.length,1);assert.equal(f.legacyCount.value,1);assert.equal(f.workspace.value.project_id,project);assert.equal(f.calls.filter(x=>x[1]==='POST').length,1);assert.equal(f.calls.find(x=>x[1]==='POST')[2].action,'inspect');}finally{f.dispose();}
});
test('native key boundaries and UTF8 BOM or malformed UTF16 never silently change a key or value',()=>{
 const long='汉'.repeat(83)+'x';assert.equal(Buffer.from(helper.memcachedKeyBase64(long,'utf8'),'base64').length,250);
 assert.equal(Buffer.from(helper.memcachedKeyBase64('a'.repeat(250),'utf8'),'base64').length,250);
 assert.equal(Buffer.from(helper.memcachedKeyBase64('\x00'.repeat(186),'utf8'),'base64').length,186);
 assert.throws(()=>helper.memcachedKeyBase64('\x00'.repeat(187),'utf8'),/186/);
 assert.throws(()=>helper.memcachedInputBytes('\ud800','utf8',250),/Unicode/);
 const original='\ufeff实际内容';const encoded=helper.memcachedInputBytes(original,'utf8',48*1024);
 assert.equal(helper.memcachedValueText(encoded,'utf8'),original);
});
test('actual manager preserves maximum uint64 CAS, binary values and original TTL/flags',async()=>{
 const f=fixture(([path,method,input])=>path.endsWith('/workspace')&&input?.action==='cache'?{...descriptor(),cache:{action:input.cache.action,found:true,changed:false,value_base64:'/wANCoA=',value_bytes:5,cas:'18446744073709551615',flags:4294967295,ttl_remaining:42}}:undefined);
 try{
  await f.open(app);f.keyText.value='键\x00\r\n';await nextTick();await f.cache('get');
  assert.equal(f.cas.value,'18446744073709551615');assert.equal(f.flags.value,4294967295);assert.equal(f.ttl.value,42);assert.equal(f.valueMode.value,'base64');assert.equal(f.valueText.value,'/wANCoA=');
  await f.cache('cas');const request=f.calls.filter(x=>x[2]?.action==='cache').at(-1)[2].cache;
  assert.equal(request.cas,'18446744073709551615');assert.equal(request.value_base64,'/wANCoA=');assert.equal(request.flags,4294967295);assert.equal(request.ttl_seconds,42);
  assert.equal(request.key_base64,Buffer.from('键\x00\r\n').toString('base64'));assert.equal(f.cas.value,'');
 }finally{f.dispose();}
});
test('an unknown cache write is a single POST and never a silent second write or clear',async()=>{
 const f=fixture(([path,,body])=>{if(path.endsWith('/workspace')&&body?.cache?.action==='add')throw new Error('unknown transport');});
 try{await f.open(app);f.keyText.value='key';f.valueText.value='value';await nextTick();await f.cache('add');assert.match(f.error.value,/未自动|不自动/);assert.equal(f.calls.filter(x=>x[2]?.cache?.action==='add').length,1);assert.equal(f.valueText.value,'value');assert(!f.calls.some(x=>(JSON.stringify(x[2])||'').includes('flush')));}finally{f.dispose();}
});
test('double confirmation cannot dispatch two original restart commands',async()=>{
 const f=fixture();
 try{await f.open(app);await Promise.all([f.control('restart'),f.control('restart')]);const commands=f.calls.filter(x=>x[0].endsWith('/controls')&&x[1]==='POST');assert.equal(commands.length,1);assert.match(commands[0][3],/^[a-f0-9]{32}$/);assert.equal(commands[0][2].acknowledge_cache_loss,true);assert.equal(commands[0][2].expected_runtime_sha256,runtime);}finally{f.dispose();}
});
test('old actor or reduced authority cannot adopt a late cache reply',async()=>{
 let release;let entered;
 const started=new Promise(r=>entered=r);
 const f=fixture(([path,,body])=>path.endsWith('/workspace')&&body?.cache?new Promise(r=>{release=r;entered();}):undefined);
 try{
  await f.open(app);f.keyText.value='key';await nextTick();const pending=f.cache('get');await started;f.props.fullAdmin=false;await nextTick();
  release({...descriptor(),cache:{action:'get',found:true,changed:false,value_base64:Buffer.from('private old actor').toString('base64'),cas:'123',flags:0,ttl_remaining:-1}});await pending;
  assert.equal(f.visible.value,false);assert.equal(f.valueText.value,'');assert.equal(f.cas.value,'');assert.equal(f.workspace.value,undefined);
 }finally{f.dispose();}
});
test('unknown operation is retained and readonly observation never creates a new control request',async()=>{
 const request='1'.repeat(32),row={operation:{format:1,request_id:request,project_id:project,actor_id:actor,input:{action:'stop',expected_runtime_sha256:runtime,acknowledge_cache_loss:true}},state:'unknown'};
 const f=fixture(([path,method])=>path.includes('/controls/'+request)&&method==='GET'?row:undefined);
 try{await f.open(app);f.history.value=[row];await f.observe(row);assert.equal(f.calls.filter(x=>x[1]==='POST'&&!x[0].endsWith('/workspace')).length,0);assert.equal(f.history.value[0].operation.request_id,request);}finally{f.dispose();}
});
test('Socket installation has no port, raw UID, arbitrary image or command, and polls the exact original install',async()=>{
 const job='2'.repeat(32);
 const f=fixture(([path,method])=>{
  if(path==='/app-registry/memcached/install'&&method==='POST')return{job_id:job};
  if(path==='/app-registry/memcached/installs/'+job&&method==='GET')return{app_id:'memcached',job_id:job,provider:'compose',version:app.version,state_known:true,state:'succeeded'};
 });
 try{await f.open(app,'install');await f.install();const input=f.calls.find(x=>x[0]==='/app-registry/memcached/install')[2];assert.deepEqual(input,{expected_version:app.version,expected_sha256:app.sha256,settings:{site_id:''}});await f.checkInstallation();assert.match(f.installStatus.value,/原安装已完成/);assert(f.calls.some(x=>x[0]==='/app-registry/memcached/installs/'+job));assert(!f.installStatus.value.includes('当前健康'));}finally{f.dispose();}
});
test('actual store selects the independent Socket workspace before the legacy port prompt',()=>{
 const appSource=readFileSync(new URL('../web/src/App.vue',import.meta.url),'utf8');
 const install=appSource.slice(appSource.indexOf('async function installRegistryApp'),appSource.indexOf('const showPanelRuntime'));
 assert(install.indexOf('app.version === "1.6.45-compat4"')<install.indexOf('const defaultPort'));
 assert(vue.includes('memcachedUnixVersion'));assert(!/localStorage|sessionStorage|console\.log/.test(vue));
});
function pendingReview(owner=actor){return{operation:{format:1,request_id:'1'.repeat(32),project_id:project,actor_id:owner,input:{action:'stop',expected_runtime_sha256:runtime,acknowledge_cache_loss:true}},state:'unknown'};}
function reviewDescriptor(row){return{format:1,request_id:row.operation.request_id,project_id:project,operation_sha256:'f'.repeat(64),original_outcome:'unknown',current_state:'running',runtime_sha256:runtime};}
function observedDescriptor(row){const v=reviewDescriptor(row);delete v.current_state;delete v.runtime_sha256;v.observation={format:1,request_id:v.request_id,project_id:project,operation_sha256:v.operation_sha256,state:'observed',final_state:'running',runtime_sha256:runtime,reviewer_id:actor,observed_at:'2026-10-24T12:00:00.123456789Z'};return v;}

test('retired workspace requires original retirement identity and never becomes running or removable again',()=>{
 const v={...descriptor(),state:'retired',healthy:false,retirement_request_id:'1'.repeat(32)};
 assert(helper.validMemcachedWorkspace(v,project));
 for(const patch of[{retirement_request_id:undefined},{retirement_request_id:'other'},{retirement_supported:true},{healthy:true}])assert(!helper.validMemcachedWorkspace({...v,...patch},project));
 assert(!helper.validMemcachedWorkspace({...descriptor(),retirement_request_id:'1'.repeat(32)},project));
});
test('actual retirement requires stopped supported instance and exact typed name then posts only one bound command',async()=>{
 let retired=false,request='';const prompts=[];
 const f=fixture(([path,method,input,key])=>{
  if(path.endsWith('/workspace'))return{...descriptor(),name:'own-cache',state:retired?'retired':'stopped',healthy:false,retirement_supported:!retired,...(retired?{retirement_request_id:request}:{})};
  if(path.endsWith('/controls')&&method==='POST'){
   assert.equal(input.action,'retire');retired=true;request=key;
   return{operation:{format:1,request_id:key,project_id:project,actor_id:actor,input},state:'completed',result:{format:1,request_id:key,project_id:project,operation_sha256:'f'.repeat(64),state:'completed',final_state:'retired',runtime_sha256:'9'.repeat(64)}};
  }
 },undefined,async(message,title,options)=>{prompts.push({message,title,options});assert.equal(options.inputValue,'');assert.equal(options.inputValidator('own-cache'),true);assert.notEqual(options.inputValidator('other'),true);return{value:'own-cache'};});
 try{
  await f.open(app);await Promise.all([f.control('retire'),f.control('retire')]);
  const commands=f.calls.filter(x=>x[0].endsWith('/controls')&&x[1]==='POST');assert.equal(commands.length,1);
  assert.deepEqual(commands[0][2],{action:'retire',expected_runtime_sha256:runtime,acknowledge_cache_loss:false,acknowledge_removal:true,confirm_name:'own-cache'});
  assert.equal(f.workspace.value.state,'retired');assert.equal(f.workspace.value.healthy,false);assert.equal(f.workspace.value.retirement_request_id,request);
  const n=f.calls.length;await f.control('start');await f.control('retire');assert.equal(f.calls.length,n);
  assert(prompts.every(p=>p.message.includes('保留')&&p.message.includes('网站文件')));
 }finally{f.dispose();}
});
test('running old-capability wrong-name or revoked retirement never dispatches a native command',async()=>{
 for(const kind of['running','unsupported','wrong-name','revoked']){
  let release;let entered;const started=new Promise(r=>entered=r);
  const f=fixture(([path])=>path.endsWith('/workspace')?{...descriptor(),name:'own-cache',state:kind==='running'?'running':'stopped',healthy:kind==='running',retirement_supported:kind!=='unsupported'}:undefined,undefined,async()=>kind==='revoked'?new Promise(r=>{release=r;entered();}):{value:'wrong'});
  try{
   await f.open(app);const pending=f.control('retire');
   if(kind==='revoked'){await started;f.props.fullAdmin=false;await nextTick();release({value:'own-cache'});}
   await pending;assert.equal(f.calls.filter(x=>x[0].endsWith('/controls')&&x[1]==='POST').length,0,kind);
  }finally{f.dispose();}
 }
});
test('lost retirement reply retains original key and only observes server history, never repeats removal',async()=>{
 let original;
 const f=fixture(([path,method,input,key])=>{
  if(path.endsWith('/workspace'))return{...descriptor(),name:'own-cache',state:'stopped',healthy:false,retirement_supported:true};
  if(path==='/app-registry/memcached/controls')return{records:original?[original]:[],truncated:false};
  if(path.endsWith('/controls')&&method==='POST'){original={operation:{format:1,request_id:key,project_id:project,actor_id:actor,input},state:'unknown'};throw Error('reply lost');}
 },undefined,async()=>({value:'own-cache'}));
 try{
  await f.open(app);await f.control('retire');assert.match(f.error.value,/不自动重发/);assert.equal(f.history.value[0].operation.request_id,original.operation.request_id);
  await f.control('retire');assert.equal(f.calls.filter(x=>x[0].endsWith('/controls')&&x[1]==='POST').length,1);
 }finally{f.dispose();}
});
test('retirement observation remains original-unknown and cannot be borrowed by a start or stop',()=>{
 const row=pendingReview();row.operation.input={action:'retire',expected_runtime_sha256:runtime,acknowledge_cache_loss:false,acknowledge_removal:true,confirm_name:'own-cache'};
 const view={...reviewDescriptor(row),current_state:'retired'};assert(helper.validMemcachedControlRow(row,actor));assert(helper.validMemcachedControlReview(row.operation,view));
 const observed=observedDescriptor(row);observed.observation.final_state='retired';assert(helper.validMemcachedControlReview(row.operation,observed));
 const old=pendingReview().operation;assert(!helper.validMemcachedControlReview(old,view));assert(!helper.validMemcachedControlReview(old,observed));
 for(const patch of[{acknowledge_removal:false},{confirm_name:''},{confirm_name:'../other'},{acknowledge_cache_loss:true}]){
  assert(!helper.validMemcachedControlRow({...row,operation:{...row.operation,input:{...row.operation.input,...patch}}},actor));
 }
});
test('independent observations cannot masquerade as original success or grant a foreign command',()=>{
 const row=pendingReview(other),v=observedDescriptor(row);
 assert(!helper.validMemcachedControlRow(row,actor));assert(helper.validMemcachedControlRow(row,actor,true));
 assert(!helper.validMemcachedControlRow({...row,state:'completed',result:v.observation},actor,true));
 assert(helper.validMemcachedControlReview(row.operation,v));
 for(const patch of[{current_state:'running'},{runtime_sha256:runtime},{original_outcome:'completed'},{project_id:other},{operation_sha256:'e'.repeat(64)}])assert(!helper.validMemcachedControlReview(row.operation,{...v,...patch}));
 for(const patch of[{state:'completed'},{reviewer_id:''},{observed_at:'yesterday'},{observed_at:'2026-02-31T12:00:00Z'},{runtime_sha256:''},{final_state:'healthy'}]){
  const result={...v.observation,...patch};assert(!helper.validMemcachedControlResult(row.operation,result));
 }
});
test('another current administrator may preview a pending original without inheriting its command identity',async()=>{
 const row=pendingReview(other);
 const f=fixture(([path,method])=>path==='/app-registry/memcached/controls'?{records:[row],truncated:false}:path.endsWith('/review')&&method==='GET'?reviewDescriptor(row):undefined);
 try{await f.open(app);assert.equal(f.history.value[0].operation.actor_id,other);await f.observe(f.history.value[0],true);assert(!f.calls.some(x=>x[0].endsWith('/close')));await f.previewReview(f.history.value[0]);assert.equal(f.reviewView.value.current_state,'running');assert.equal(f.calls.filter(x=>x[0].endsWith('/review')&&x[1]==='GET').length,1);assert.equal(f.calls.filter(x=>x[0].endsWith('/review')&&x[1]==='POST').length,0);}finally{f.dispose();}
});
test('double review confirmation sends one closed acknowledgement and no native command',async()=>{
 const row=pendingReview(other);
 const f=fixture(([path,method])=>path.endsWith('/review')?(method==='GET'?reviewDescriptor(row):observedDescriptor(row)):undefined);
 try{await f.open(app);f.history.value=[row];await f.previewReview(f.history.value[0]);await Promise.all([f.commitReview(),f.commitReview()]);const posts=f.calls.filter(x=>x[0].endsWith('/review')&&x[1]==='POST');assert.equal(posts.length,1);assert.deepEqual(posts[0][2],{expected_runtime_sha256:runtime,acknowledge_original_unknown:true});assert.equal(f.history.value.length,0);assert.equal(f.reviewView.value.observation.state,'observed');assert(!f.calls.some(x=>x[0].endsWith('/controls')&&x[1]==='POST'));assert(!f.workspace.value);}finally{f.dispose();}
});
test('lost review reply clears the confirmation and requires a readonly original preview',async()=>{
 const row=pendingReview();let lost=true;
 const f=fixture(([path,method])=>{if(!path.endsWith('/review'))return;if(method==='GET')return lost?reviewDescriptor(row):observedDescriptor(row);lost=false;throw new Error('lost review reply');});
 try{await f.open(app);f.history.value=[row];await f.previewReview(f.history.value[0]);await f.commitReview();await f.commitReview();assert.equal(f.calls.filter(x=>x[0].endsWith('/review')&&x[1]==='POST').length,1);assert.match(f.error.value,/不自动重发/);assert(!f.reviewView.value);assert.equal(f.history.value[0].state,'unknown');await f.previewReview(f.history.value[0]);assert.equal(f.reviewView.value.observation.state,'observed');assert.equal(f.history.value[0].state,'unknown');}finally{f.dispose();}
});
test('permission revoked while confirming review or close cannot submit a stale POST',async()=>{
 for(const close of[false,true]){
  let release,entered;const waiting=new Promise(r=>entered=r),row=pendingReview();
  const f=fixture(([path])=>path.endsWith('/review')?reviewDescriptor(row):undefined,()=>new Promise(r=>{release=r;entered();}));
  try{await f.open(app);f.history.value=[row];if(!close)await f.previewReview(f.history.value[0]);const work=close?f.observe(f.history.value[0],true):f.commitReview();await waiting;f.props.fullAdmin=false;await nextTick();release();await work;assert.equal(f.calls.filter(x=>(x[0].endsWith('/review')||x[0].endsWith('/close'))&&x[1]==='POST').length,0);assert(!f.reviewView.value);assert.equal(f.visible.value,false);}finally{f.dispose();}
 }
});
test('late cross-actor review preview is discarded on account change',async()=>{
 let release,entered;const waiting=new Promise(r=>entered=r),row=pendingReview(other);
 const f=fixture(([path])=>path.endsWith('/review')?new Promise(r=>{release=r;entered();}):undefined);
 try{await f.open(app);f.history.value=[row];const work=f.previewReview(f.history.value[0]);await waiting;f.props.actor=other;await nextTick();release(reviewDescriptor(row));await work;assert(!f.reviewView.value);assert(!f.reviewRow.value);assert.equal(f.history.value.length,0);}finally{f.dispose();}
});
