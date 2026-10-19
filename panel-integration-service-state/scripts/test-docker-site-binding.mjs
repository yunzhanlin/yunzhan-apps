import test from 'node:test';import assert from 'node:assert/strict';import {readFileSync} from 'node:fs';import ts from '../web/node_modules/typescript/lib/typescript.js';
const source=readFileSync(new URL('../web/src/DockerManager.vue',import.meta.url),'utf8'),start=source.indexOf('async function bindProjectSite('),end=source.indexOf('async function projectAction(',start);assert(start>0&&end>start);
const js=ts.transpileModule(source.slice(start,end),{compilerOptions:{target:ts.ScriptTarget.ES2022}}).outputText;
const job='a'.repeat(32),site='b'.repeat(32);
function fixture(response){
 let clock=0;const calls=[],messages=[],saved=new Map(),b={bindingProject:{value:{id:'d'.repeat(32)}},bindingForm:{value:{name:'binding fixture',slug:'binding-fixture',domain:'fixture.example'}},bindingOpen:{value:true},busy:{value:false},randomId:()=> 'c'.repeat(32),Date:{now:()=>clock},setTimeout(fn,ms){clock+=ms;queueMicrotask(fn);},sessionStorage:{getItem:k=>saved.get(k)||null,setItem:(k,v)=>saved.set(k,v),removeItem:k=>saved.delete(k)},ElMessage:Object.fromEntries(['success','error'].map(k=>[k,v=>messages.push([k,v])])),props:{async api(...args){calls.push(args);return args[1]==='POST'?{job_id:job}:response(calls.filter(x=>x[1]!=='POST').length);}}};
 return{b,calls,messages,saved,run:new Function('b','with(b){'+js+';return bindProjectSite;}')(b)};
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
