import test from 'node:test';import assert from 'node:assert/strict';import {readFileSync} from 'node:fs';
import ts from '../web/node_modules/typescript/lib/typescript.js';
import {ref,reactive,computed,watch,effectScope} from '../web/node_modules/vue/index.mjs';
const permissionSource=readFileSync(new URL('../web/src/menuPermissions.ts',import.meta.url),'utf8');
const permissionJS=ts.transpileModule(permissionSource,{compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.CommonJS}}).outputText;
const permissionExports={};new Function('exports',permissionJS)(permissionExports);const {canOpenAppModule}=permissionExports;
import * as createRequestExports from '../web/src/dockerCreateRequest.ts';
const randomExports={};new Function('exports',ts.transpileModule(readFileSync(new URL('../web/src/randomId.ts',import.meta.url),'utf8'),{compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.CommonJS}}).outputText)(randomExports);
const source=readFileSync(new URL('../web/src/DockerManager.vue',import.meta.url),'utf8').split('<script setup lang="ts">')[1].split('</script>')[0];
const ast=ts.createSourceFile('DockerManager.ts',source,ts.ScriptTarget.Latest,true,ts.ScriptKind.TS);
const statements=ast.statements.filter(n=>!ts.isImportDeclaration(n)&&!(ts.isExpressionStatement(n)&&n.expression.expression?.getText(ast)==='defineExpose'));
const js=ts.transpileModule(statements.map(n=>n.getText(ast)).join('\n'),{compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.ESNext}}).outputText;
const names=['visible','busy','loading','credentials','credentialsOpen','logs','logsName','logsOpen','overview','containers','images','projects','networks','volumes','templates','bindingProject','bindingForm','bindingOpen','projectOpen','projectForm','createProject','newProject','pendingCreate','originalCreateJob','createRecoveryError','createBlocked','checkOriginalCreate','acknowledgeFailedCreate','showCredentials','showLogs','showProjectLogs','removeContainer','removeImage','removeProject','removeNetwork','removeVolume','pull','createVolume','load','projectAction','bindProjectSite','waitJob','contextToken'];
const deferred=()=>{let resolve,reject;const promise=new Promise((a,b)=>{resolve=a;reject=b});return{promise,resolve,reject};};
const project={id:'a'.repeat(32),name:'fixture-project',engine_name:'panel_fixture'},container={Id:'b'.repeat(64),Names:['/fixture-container'],State:'exited',Labels:{}},image={Id:'sha256:'+'c'.repeat(64)},network={Id:'d'.repeat(64),Name:'fixture-network'},volume={Name:'fixture-volume'};
function response(url){if(url==='/docker')return{available:true,version:'fixture-engine'};const key=url.split('/').at(-1);return{[key]:[]};}
function fixture(api=async url=>response(url),prompt=async()=>({value:'fixture'})){
 const scope=effectScope(),calls=[],messages=[],saved=new Map(),timers=[],props=reactive({csrf:'fixture-original-session',access:{role:'admin',user_id:'d'.repeat(32),menu_ids:['system-tools','runtimes']},api:(...args)=>{calls.push(args);return api(...args);}});
 const b={...createRequestExports,ref,computed,watch,canOpenAppModule,defineProps:()=>props,ElMessage:Object.fromEntries(['success','warning','error'].map(k=>[k,v=>messages.push([k,v])])),ElMessageBox:{prompt},randomId:randomExports.randomId,formatPanelDateTime:()=> 'fixture-time',sessionStorage:{getItem:k=>saved.get(k)||null,setItem:(k,v)=>saved.set(k,v),removeItem:k=>saved.delete(k)},setTimeout(fn){timers.push(fn);},onBeforeUnmount(fn){b.dispose=fn;}};
 const x=scope.run(()=>new Function('b','with(b){'+js+';return {'+names.join(',')+'};}')(b));x.visible.value=true;
 return{x,props,calls,messages,saved,timers,close(){b.dispose?.();scope.stop();}};
}
const flush=async()=>{for(let i=0;i<8;i++)await Promise.resolve();};
const until=async(predicate)=>{const deadline=Date.now()+5000;while(!predicate()&&Date.now()<deadline)await new Promise(resolve=>setTimeout(resolve,5));assert(predicate(),'actual asynchronous fingerprint did not settle');};
test('actual Docker credentials are cleared and late private replies cannot reopen a closed, replaced or unmounted manager',async()=>{
 for(const change of [f=>f.x.visible.value=false,f=>f.props.csrf='replacement-session',f=>f.props.access=null,f=>f.close()]){const d=deferred(),f=fixture(()=>d.promise);try{f.x.credentials.value={password:'previous-private'};f.x.credentialsOpen.value=true;const pending=f.x.showCredentials(project);change(f);d.resolve({password:'late-private'});await pending;assert.equal(f.x.credentials.value,undefined);assert.equal(f.x.credentialsOpen.value,false);assert.equal(f.calls.length,1);}finally{f.close();}}
});
test('actual Docker private reads cannot start without current admin authority',async()=>{
 for(const access of [null,{role:'viewer',menu_ids:['overview']},{role:'admin',menu_ids:['overview']}]){const f=fixture(async()=>assert.fail('unauthorized Docker request'));try{f.props.access=access;await f.x.showCredentials(project);await f.x.showLogs(container);assert.equal(f.calls.length,0);}finally{f.close();}}
});
test('actual container and project log responses cannot refill a closed log dialog or replacement account',async()=>{
 for(const method of ['showLogs','showProjectLogs'])for(const change of [f=>f.x.logsOpen.value=false,f=>f.props.csrf='replacement-session']){const d=deferred(),f=fixture(()=>d.promise);try{f.x.logsOpen.value=true;f.x.logs.value='old-private';const pending=f.x[method](method==='showLogs'?container:project);change(f);d.resolve({logs:'late-private'});await pending;assert.equal(f.x.logs.value,'');assert.equal(f.x.logsOpen.value,false);}finally{f.close();}}
});
test('all actual Docker prompt actions stop before mutation when the account changes, window closes or component unmounts',async()=>{
 for(const [method,item] of [['removeContainer',container],['removeImage',image],['removeProject',project],['removeNetwork',network],['removeVolume',volume],['pull',undefined],['createVolume',undefined]])for(const change of [f=>f.props.csrf='replacement-session',f=>f.x.visible.value=false,f=>f.close()]){const d=deferred(),f=fixture(async()=>assert.fail('obsolete confirmation submitted'),()=>d.promise);try{const pending=f.x[method](item);change(f);d.resolve({value:'fixture'});await pending;assert.equal(f.calls.length,0);}finally{f.close();}}
});
test('late list data and finalizers cannot populate or clear replacement manager state',async()=>{
 const d=deferred(),f=fixture(()=>d.promise);try{const pending=f.x.load();f.props.csrf='replacement-session';f.x.loading.value=true;d.resolve({available:true,containers:[container],images:[image],projects:[project],networks:[network],volumes:[volume],templates:[{id:'old-private'}]});await pending;assert.equal(f.x.overview.value,null);for(const name of ['containers','images','projects','networks','volumes','templates'])assert.deepEqual(f.x[name].value,[]);assert.equal(f.x.loading.value,true);}finally{f.close();}
});
test('latest actual credential and log request wins, without cross-resource private display',async()=>{
 for(const method of ['showCredentials','showLogs','showProjectLogs']){const a=deferred(),z=deferred();let n=0;const f=fixture(()=>++n===1?a.promise:z.promise);try{const item=method==='showLogs'?container:project,p=f.x[method](item),q=f.x[method]({...item,id:'f'.repeat(32),Id:'f'.repeat(64),name:'new-project',Names:['/new-container']});z.resolve(method==='showCredentials'?{password:'new-private'}:{logs:'new-private'});await q;a.resolve(method==='showCredentials'?{password:'old-private'}:{logs:'old-private'});await p;assert.equal(method==='showCredentials'?f.x.credentials.value.password:f.x.logs.value,'new-private');}finally{f.close();}}
});
test('closing an actual submitted Docker operation stops browser polling, preserves the original backend job and emits no success',async()=>{
 const f=fixture(async()=>({job_id:'1'.repeat(32),state:'running',kind:'compose',project_id:project.id}));try{const pending=f.x.projectAction(project,'start');await flush();assert.equal(f.calls.length,1);assert.equal(f.timers.length,1);f.x.visible.value=false;f.x.busy.value=true;f.timers.shift()();await pending;assert.equal(f.calls.length,1);assert(!f.messages.some(([k])=>k==='success'));assert.equal(f.x.busy.value,true);}finally{f.close();}
});
test('closing the actual binding context retains the original pending request and never continues polling or claims success',async()=>{
 const d=deferred(),f=fixture(()=>d.promise);try{f.x.bindingProject.value=project;f.x.bindingOpen.value=true;f.x.bindingForm.value={name:'fixture-site',slug:'fixture-site',domain:'fixture.example'};const pending=f.x.bindProjectSite();assert.equal(f.calls.length,1);assert.equal(f.saved.size,1);f.x.bindingOpen.value=false;d.resolve({job_id:'2'.repeat(32)});await pending;assert.equal(f.timers.length,0);assert.equal(f.calls.length,1);assert.equal(f.saved.size,1);assert(!f.messages.some(([k])=>k==='success'));}finally{f.close();}
});
test('normal current credential and log reads still show their original response',async()=>{
 const f=fixture(async url=>url.endsWith('/credentials')?{password:'same-scope'}:{logs:'same-scope-log'});try{await f.x.showCredentials(project);assert.equal(f.x.credentials.value.password,'same-scope');assert(f.x.credentialsOpen.value);await f.x.showLogs(container);assert.equal(f.x.logs.value,'same-scope-log');assert(f.x.logsOpen.value);}finally{f.close();}
});
test('same-scope destructive confirmation keeps its original endpoint and body without retry',async()=>{
 const f=fixture(async(url,method)=>method==='DELETE'?{}:response(url),async()=>({value:'fixture-volume'}));try{await f.x.removeVolume(volume);const writes=f.calls.filter(c=>c[1]==='DELETE');assert.equal(writes.length,1);assert.equal(writes[0][0],'/docker/volumes/fixture-volume');assert.deepEqual(writes[0][2],{confirm_name:'fixture-volume'});assert(f.messages.some(([k])=>k==='success'));}finally{f.close();}
});
test('current authority is supplied by the actual parent, and normal release runs the context gate',()=>{
 const app=readFileSync(new URL('../web/src/App.vue',import.meta.url),'utf8'),blocks=[...app.matchAll(/<DockerManager\b[^>]*\/>/g)].map(m=>m[0]);assert.equal(blocks.length,1);assert(blocks[0].includes(':csrf="csrf"'));assert(blocks[0].includes(':access="accessPlan"'));
 const release=readFileSync(new URL('../packaging/build-release.sh',import.meta.url),'utf8');assert(release.includes('node --test scripts/test-docker-scope.mjs'));
});
test('actual Docker job inspector refuses malformed original identities and impossible successful states without polling',async()=>{
 for(const value of [{job_id:'invalid',state:'succeeded'},{job_id:'1'.repeat(32),state:'unknown'},{job_id:'1'.repeat(32),state:'succeeded',error:'original failure'},{job_id:'1'.repeat(32),state:'succeeded',kind:'foreign'}]){const f=fixture();try{await assert.rejects(f.x.waitJob(value,f.x.contextToken()),/身份|状态/);assert.equal(f.calls.length,0);}finally{f.close();}}
});
test('actual Docker job inspector never adopts a foreign response job, kind, project or success error',async()=>{
 for(const change of [{job_id:'2'.repeat(32)},{kind:'foreign'},{project_id:'3'.repeat(32)},{state:'succeeded',error:'original failure'}]){const original={job_id:'1'.repeat(32),state:'running',kind:'compose',project_id:project.id},f=fixture(async()=>({...original,state:'succeeded',...change}));try{const pending=assert.rejects(f.x.waitJob(original,f.x.contextToken(),true,project.id),/身份|状态/);await flush();assert.equal(f.timers.length,1);f.timers.shift()();await pending;assert.equal(f.calls.length,1);assert.equal(f.calls[0][0],'/docker/job-observations/'+original.job_id);}finally{f.close();}}
});
test('actual Docker job inspector completes the same original Compose identity without another submission',async()=>{
 const original={job_id:'1'.repeat(32),state:'running',kind:'compose',project_id:project.id},f=fixture(async()=>({...original,state:'succeeded'}));try{const pending=f.x.waitJob(original,f.x.contextToken(),true,project.id);await flush();f.timers.shift()();const result=await pending;assert.equal(result.job_id,original.job_id);assert.equal(result.state,'succeeded');assert.equal(f.calls.length,1);assert(!f.calls.some(c=>c[1]==='POST'));}finally{f.close();}
});
test('actual create-project callback closes its dialog only after the same original queued Compose job succeeds',async()=>{
 const original={job_id:'f3afa0b3b32fcea11fcafd9fcb90a113',kind:'compose',project_id:'e6d706e3c86fac25f5e00cfd3045609d',state:'queued'};
 const f=fixture(async(url,method)=>{
  if(method==='POST'){assert.equal(url,'/docker/projects');return original;}
  if(url==='/docker/job-observations/'+original.job_id)return{...original,state:'succeeded',message:'Compose 作业完成'};
  return response(url);
 });try{
  f.x.projectOpen.value=true;f.x.projectForm.value={name:'commercial-static-fixture',mode:'template',templateId:'nginx-static',hostPort:'23862',compose:''};
  const p=f.x.createProject();await until(()=>f.timers.length===1);assert(f.x.projectOpen.value);f.timers.shift()();await p;
  assert.equal(f.x.projectOpen.value,false);assert(f.messages.some(([k])=>k==='success'));assert.equal(f.calls.filter(c=>c[1]==='POST').length,1);assert.equal(f.x.busy.value,false);
 }finally{f.close();}
});
test('lost actual create reply retains one actor-bound request and only GET resolves the original success',async()=>{
 const original={job_id:'1'.repeat(32),kind:'compose',project_id:'2'.repeat(32),state:'succeeded'};
 const f=fixture(async(url,method)=>{if(method==='POST')throw new Error('original reply lost');if(url.startsWith('/docker/project-requests/'))return{found:true,job_id:original.job_id,project_id:original.project_id,job:original};return response(url)});
 try{
  f.x.projectOpen.value=true;await f.x.createProject();assert(f.x.pendingCreate.value);assert.equal(f.saved.size,1);assert(f.x.projectOpen.value);assert(f.x.createRecoveryError.value.includes('lost'));const key=f.x.pendingCreate.value.key;
  await f.x.createProject();assert.equal(f.calls.filter(c=>c[1]==='POST').length,1);
  await f.x.checkOriginalCreate();assert.equal(f.calls.filter(c=>c[1]==='POST').length,1);assert(f.calls.some(c=>c[0]==='/docker/project-requests/'+key));assert.equal(f.saved.size,0);assert.equal(f.x.pendingCreate.value,null);assert.equal(f.x.projectOpen.value,false);
 }finally{f.close();}
});
test('unknown, absent and foreign original create receipts never permit another POST or discard the request',async()=>{
 const original={job_id:'1'.repeat(32),kind:'compose',project_id:'2'.repeat(32),state:'succeeded'};
 for(const value of [{found:false},{found:true,job_id:original.job_id,project_id:original.project_id,pending:true},{found:true,job_id:original.job_id,project_id:original.project_id,job:{...original,job_id:'3'.repeat(32)}},{found:true,job_id:original.job_id,project_id:original.project_id,job:{...original,state:'unknown'}}]){
  const f=fixture(async(url,method)=>{if(method==='POST')throw new Error('lost reply');return value});try{f.x.projectOpen.value=true;await f.x.createProject();await f.x.checkOriginalCreate();f.x.acknowledgeFailedCreate();await f.x.createProject();assert.equal(f.calls.filter(c=>c[1]==='POST').length,1);assert.equal(f.saved.size,1);assert(f.x.pendingCreate.value);assert(f.x.createRecoveryError.value);assert(!f.messages.some(([k])=>k==='success'));}finally{f.close();}
 }
});
test('same callback cannot dispatch twice while its original asynchronous fingerprint or POST is pending',async()=>{
 const d=deferred(),f=fixture(()=>d.promise);
 try{f.x.projectOpen.value=true;const first=f.x.createProject();await f.x.createProject();await until(()=>f.calls.length===1);f.x.projectOpen.value=false;d.resolve({job_id:'1'.repeat(32),kind:'compose',project_id:'2'.repeat(32),state:'queued'});await first;assert.equal(f.calls.length,1);assert.equal(f.saved.size,1);assert(!f.messages.some(([k])=>k==='success'));}finally{f.close();}
});
test('only an explicit pre-dispatch rejection can release the same original pending request for correction',async()=>{
 for(const definitive of [false,true]){
  const f=fixture(async()=>{const e=new Error('original validation rejection');Object.assign(e,{status:400,requestNotAccepted:definitive});throw e});
  try{f.x.projectOpen.value=true;await f.x.createProject();assert.equal(f.calls.length,1);assert.equal(f.saved.size,definitive?0:1);assert.equal(Boolean(f.x.pendingCreate.value),!definitive);}finally{f.close();}
 }
});
