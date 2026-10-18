import test from 'node:test';import assert from 'node:assert/strict';
import fs from 'node:fs';
import ts from '../web/node_modules/typescript/lib/typescript.js';
const source=fs.readFileSync(new URL('../web/src/memcachedUpdateIdentity.ts',import.meta.url),'utf8');
const js=ts.transpileModule(source,{compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.ESNext}}).outputText;
const {MemcachedUpdateIdentity}=await import('data:text/javascript;base64,'+Buffer.from(js).toString('base64'));
const randomSource=fs.readFileSync(new URL('../web/src/randomId.ts',import.meta.url),'utf8');
const {randomId}=await import('data:text/javascript;base64,'+Buffer.from(ts.transpileModule(randomSource,{compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.ESNext}}).outputText).toString('base64'));
const actor='a'.repeat(32),project='b'.repeat(32),key='c'.repeat(32);
const input={expected_version:'1.6.45-compat2',expected_sha256:'d'.repeat(64),expected_project_sha256:'e'.repeat(64),acknowledge_cache_loss:true};
function storage(){const data=new Map();return{data,getItem:k=>data.get(k)??null,setItem:(k,v)=>data.set(k,v),removeItem:k=>data.delete(k)}}
test('write-ahead identity survives reload and can never be begun again',()=>{
 const s=storage(),original=new MemcachedUpdateIdentity(s,actor,()=>key),ticket=original.begin(project,input);
 assert.deepEqual(ticket,{key,input});input.expected_sha256='f'.repeat(64);assert.equal(original.read(project).input.expected_sha256,'d'.repeat(64));input.expected_sha256='d'.repeat(64);
 const reload=new MemcachedUpdateIdentity(s,actor,()=> 'f'.repeat(32));assert.deepEqual(reload.read(project),ticket);assert.throws(()=>reload.begin(project,input));
 for(const state of ['unknown','reserved','prepared','pull_started','apply_started','rollback_started','needs_attention'])assert.throws(()=>reload.finish(project,key,true,state));
 assert.throws(()=>reload.finish(project,key,false,'committed'));assert.deepEqual(reload.read(project),ticket);
});
test('only a bound known terminal request may release its local identity',()=>{
 for(const state of ['committed','rolled_back','failed_safe','closed_without_submission']){const s=storage(),i=new MemcachedUpdateIdentity(s,actor,()=>key);i.begin(project,input);assert.throws(()=>i.finish(project,'f'.repeat(32),true,state));assert.throws(()=>i.finish(project,key,false,state));i.finish(project,key,true,state);assert.equal(i.read(project),undefined)}
});
test('other accounts or projects never adopt this original identity',()=>{
 const s=storage(),i=new MemcachedUpdateIdentity(s,actor,()=>key);i.begin(project,input);assert.equal(new MemcachedUpdateIdentity(s,'f'.repeat(32),()=>key).read(project),undefined);assert.equal(i.read('f'.repeat(32)),undefined);assert.throws(()=>new MemcachedUpdateIdentity(s,'admin',()=>key));
});
test('storage uncertainty is never permission to send or rotate a request',()=>{
 for(const kind of ['read','write','lost-write']){const s=storage();if(kind==='read')s.getItem=()=>{throw Error('blocked')};if(kind==='write')s.setItem=()=>{throw Error('full')};if(kind==='lost-write')s.setItem=()=>{};assert.throws(()=>new MemcachedUpdateIdentity(s,actor,()=>key).begin(project,input))}
});
test('malformed or oversized old records remain a blocking error',()=>{
 const s=storage(),i=new MemcachedUpdateIdentity(s,actor,()=>key);i.begin(project,input);const name=[...s.data.keys()][0];
 for(const raw of ['null','{}','{',' '.repeat(4097),JSON.stringify({key,input,verified:true}),JSON.stringify({key:'other',input}),JSON.stringify({key,input:{...input,acknowledge_cache_loss:false}})]){s.data.set(name,raw);assert.throws(()=>i.read(project));assert.throws(()=>i.begin(project,input));assert.equal(s.data.get(name),raw)}
});
test('no acknowledgement, wrong digest/version or extra input may be sent',()=>{
 for(const change of [{acknowledge_cache_loss:false},{expected_version:'latest'},{expected_sha256:'tag'},{expected_project_sha256:'other'},{image:'untrusted'}]){const s=storage(),i=new MemcachedUpdateIdentity(s,actor,()=>key);assert.throws(()=>i.begin(project,{...input,...change}));assert.equal(s.data.size,0)}
});
test('the ACTUAL cryptographic browser generator interoperates with the closed 32-hex native protocol',()=>{
 const s=storage(),i=new MemcachedUpdateIdentity(s,actor,randomId),ticket=i.begin(project,input);assert.match(ticket.key,/^[a-f0-9]{32}$/);assert(!ticket.key.includes('-'));assert.deepEqual(i.read(project),ticket);
 const uuid='11111111-2222-4333-8444-555555555555';assert.equal(new MemcachedUpdateIdentity(storage(),actor,()=>uuid).begin(project,input).key,uuid.replaceAll('-',''));
 for(const bad of ['c'.repeat(36),'11111111-2222-3333-4444-555555555555','111111112222-4333-8444-555555555555','X'.repeat(32)])assert.throws(()=>new MemcachedUpdateIdentity(storage(),actor,()=>bad).begin(project,input));
});
test('actual component lost-submit path schedules only original GET observation and cannot issue a second POST',async()=>{
 const component=fs.readFileSync(new URL('../web/src/MemcachedAppUpdate.vue',import.meta.url),'utf8'),script=component.split('<script setup lang="ts">')[1].split('</script>')[0];
 const tree=ts.createSourceFile('MemcachedAppUpdate.ts',script,ts.ScriptTarget.Latest,true,ts.ScriptKind.TS);
 const extract=name=>{const f=tree.statements.find(n=>ts.isFunctionDeclaration(n)&&n.name?.text===name);assert(f,'actual function missing: '+name);return f.getText(tree)};
 const submit=ts.transpileModule(extract('submit'),{compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.ESNext}}).outputText;
 let posts=0,schedules=0,observes=0,saved=false;
 const refs={plan:{value:{project_sha256:input.expected_project_sha256}},accepted:{value:true},ticket:{value:undefined},status:{value:undefined},busy:{value:false},error:{value:''},project:{value:project},version:{value:input.expected_version},digest:{value:input.expected_sha256},generation:13,abort:new AbortController(),identity:()=>({begin:()=>{saved=true;return{key,input}}}),props:{api:async(_path,method,body,original)=>{assert(saved);assert.equal(method,'POST');assert.equal(original,key);assert.deepEqual(body,input);posts++;throw Error('synthetic lost original response')}},observe:async()=>{observes++},schedule:g=>{assert.equal(g,13);schedules++}};
 const actual=new Function(...Object.keys(refs),submit+';return submit;')(...Object.values(refs));await actual();assert.equal(posts,1);assert.equal(schedules,1);assert.equal(observes,0);assert.equal(refs.ticket.value.key,key);assert.equal(refs.busy.value,false);assert.match(refs.error.value,/只能核对原任务/);await actual();assert.equal(posts,1);assert.equal(schedules,1);
 assert(!extract('schedule').includes('"POST"'));assert(extract('observe').includes('"GET"'));assert(!extract('observe').includes('"POST"'));
});
test('actual account reset cancels reads/polling and clears every old display binding before another account opens',()=>{
 const source=fs.readFileSync(new URL('../web/src/MemcachedAppUpdate.vue',import.meta.url),'utf8').split('<script setup lang="ts">')[1].split('</script>')[0],tree=ts.createSourceFile('manager.ts',source,ts.ScriptTarget.Latest,true,ts.ScriptKind.TS),node=tree.statements.find(n=>ts.isFunctionDeclaration(n)&&n.name?.text==='reset');assert(node);
 const js=ts.transpileModule(node.getText(tree),{compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.ESNext}}).outputText;
 let stopped=0;const oldAbort=new AbortController(),refs={generation:4,stopPoll:()=>stopped++,abort:oldAbort};
 for(const key of ['visible','busy','checking','accepted'])refs[key]={value:true};for(const key of ['project','version','digest','error'])refs[key]={value:'old-account-value'};for(const key of ['plan','ticket','status'])refs[key]={value:{private:'old-account'}};refs.instances={value:[{id:project}]};
 const actual=new Function(...Object.keys(refs),js+';return{run:reset,generation:()=>generation};')(...Object.values(refs));actual.run();assert.equal(actual.generation(),5);assert(oldAbort.signal.aborted);assert.equal(stopped,1);
 for(const key of ['visible','busy','checking','accepted'])assert.equal(refs[key].value,false);for(const key of ['project','version','digest','error'])assert.equal(refs[key].value,'');for(const key of ['plan','ticket','status'])assert.equal(refs[key].value,undefined);assert.deepEqual(refs.instances.value,[]);
});
test('actual safe-close action never resends update or clears an identity on an unknown/rejected closure',async()=>{
 const component=fs.readFileSync(new URL('../web/src/MemcachedAppUpdate.vue',import.meta.url),'utf8'),script=component.split('<script setup lang="ts">')[1].split('</script>')[0],tree=ts.createSourceFile('manager.ts',script,ts.ScriptTarget.Latest,true,ts.ScriptKind.TS),node=tree.statements.find(n=>ts.isFunctionDeclaration(n)&&n.name?.text==='closeUnsubmitted');assert(node);
 const js=ts.transpileModule(node.getText(tree),{compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.ESNext}}).outputText;
 for(const mode of ['unknown','wrong-key','job-exists','valid']){
  let calls=0,schedules=0;const original={key,input},reply={project_id:project,request_id:mode==='wrong-key'?'f'.repeat(32):key,job_id:mode==='job-exists'?'f'.repeat(32):'',state:'closed_without_submission',state_known:true,expected_version:input.expected_version,expected_sha256:input.expected_sha256};
  const refs={ticket:{value:original},status:{value:undefined},busy:{value:false},checking:{value:false},error:{value:''},project:{value:project},generation:8,abort:new AbortController(),schedule:g=>{assert.equal(g,8);schedules++},props:{api:async(route,method,body,id)=>{calls++;assert.equal(route,`/app-registry/memcached/instances/${project}/updates/${key}/close`);assert.equal(method,'POST');assert.equal(id,key);assert.deepEqual(body,input);if(mode==='unknown')throw Error('lost closure response');return reply}}};
  const actual=new Function(...Object.keys(refs),js+';return closeUnsubmitted;')(...Object.values(refs));await actual();assert.equal(calls,1);assert.equal(refs.ticket.value,original);assert.equal(schedules,1);assert.equal(refs.busy.value,false);if(mode==='valid')assert.equal(refs.status.value,reply);else{assert.equal(refs.status.value,undefined);assert.match(refs.error.value,/保留原编号/)}
  refs.status.value={job_id:'f'.repeat(32)};await actual();assert.equal(calls,1,'an already-bound native job must never enter non-submission closure');
 }
 assert(!node.getText(tree).includes('.finish('));assert(!node.getText(tree).includes('"/updates", "POST"'));
});
