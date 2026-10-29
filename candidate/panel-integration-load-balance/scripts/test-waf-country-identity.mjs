// Actual compiled browser continuity mechanism and component submit function.
// Memory/transport models, NOT real IndexedDB, signing or installed WAF proof.
import test from 'node:test';import assert from 'node:assert/strict';import fs from 'node:fs';import ts from '../web/node_modules/typescript/lib/typescript.js';
const read=p=>fs.readFileSync(new URL('../'+p,import.meta.url),'utf8');
const compile=source=>ts.transpileModule(source,{compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.ESNext}}).outputText;
const {CountryRequestIdentity,IndexedCountryStorage,canonicalCountrySelection,readCountryDetail}=await import('data:text/javascript;base64,'+Buffer.from(compile(read('web/src/wafCountryIdentity.ts'))).toString('base64'));
const actor='a'.repeat(32),key='b'.repeat(32),job='c'.repeat(32),hash='d'.repeat(64);
const selection={action:'download',app_version:'2.6.0',app_manifest_sha256:'e'.repeat(64),installation_sha256:'f'.repeat(64),release:'2026-10',revision:1,data_manifest_sha256:'1'.repeat(64),countries:['CN','US']};
function atomic(){const data=new Map();let tail=Promise.resolve();return{data,run(actor,write,change){const p=tail.then(()=>{const next=change(structuredClone(data.get(actor)),data.size);assert(!(!write&&(next.put||next.remove)));assert(!(next.put&&next.remove));if(next.put)data.set(actor,structuredClone(next.put));if(next.remove)data.delete(actor);return structuredClone(next.result);});tail=p.catch(()=>{});return p;}};}
function lookup(state='queued'){
 const detail={actor_id:actor,request:{id:job,state,created_at:'2026-10-20T00:00:00Z',payload_sha256:hash},selection:structuredClone(selection),read_only:true,error:['failed','needs_attention'].includes(state)?'explicit original model error':''};
 if(state==='succeeded'){detail.result_sha256=hash;detail.result={format:1,job_id:job,actor_id:actor,selection:structuredClone(selection),payload_sha256:hash,request_sha256:hash,requested_cache_plan_sha256:hash,state,error:'',data_only:true,automatic_replay_allowed:false,cache:{dataset:selection.data_manifest_sha256+'-'+hash,data_manifest_sha256:selection.data_manifest_sha256,countries:['CN','US'],release:'2026-10',revision:1,original_job_id:job,plan_sha256:hash,prepared_at:'2026-10-20T00:00:00Z',bytes:400,networks:2,published:true,reused:false,activated_nginx_policy:false}};}
 return{actor_id:actor,request_id:key,state_known:true,request:detail,read_only:true,automatic_replay_allowed:false};
}
function actualSubmit(deps){const source=read('web/src/WafCountryData.vue').split('<script setup lang="ts">')[1].split('</script>')[0],tree=ts.createSourceFile('country.vue',source,ts.ScriptTarget.Latest,true,ts.ScriptKind.TS),node=tree.statements.find(n=>ts.isFunctionDeclaration(n)&&n.name?.text==='submit');assert(node);return Function('deps','const {busy,blocked,props,page,selectionValid,generation,abort,identity,current,readOriginal,readJobs,stopTimer,scheduleOriginal,error,selected,pending,outcome,endpoint}=deps;'+compile(node.getText(tree))+';return submit;')(deps);}
function submitFixture(context){const methods=[],deps={busy:{value:false},blocked:{value:false},props:{active:true,actor,api:async(path,method,body,request)=>{methods.push({path,method,body,request});return{job_id:job,request_id:key,replayed:false,data_only:true};}},page:{value:{state:{supported:true,installation_sha256:selection.installation_sha256},available:{app_version:'2.6.0',app_manifest_sha256:selection.app_manifest_sha256,data_manifest_sha256:selection.data_manifest_sha256,release:selection.release,revision:1}}},selectionValid:{value:true},generation:1,abort:new AbortController(),identity:()=>context,current:()=>true,readOriginal:async()=>{methods.push({method:'read-original'});},readJobs:async()=>{},stopTimer(){},scheduleOriginal(){},error:{value:''},selected:{value:['CN','US']},pending:{value:undefined},outcome:{value:undefined},endpoint:'/software/nginx-waf/country-data'};return{deps,methods,submit:()=>actualSubmit(deps)};}

test('canonical country selection is detached, closed, ordered and bounded',()=>{
 const value=canonicalCountrySelection(selection);value.countries.push('ZA');assert.deepEqual(selection.countries,['CN','US']);
 for(const change of [{countries:['US','CN']},{countries:['CN','CN']},{countries:['ZZ']},{countries:[]},{countries:Array(33).fill('US')},{app_version:'2.6.0-preview'},{revision:0},{revision:1001},{revision:'1'},{release:'2026-13'},{source:'https://evil.invalid'},{installation_sha256:'x'.repeat(64)}])assert.throws(()=>canonicalCountrySelection({...selection,...change}));
});
test('two serialized tabs receive one fresh POST ticket and the same original key',async()=>{
 const store=atomic();let random=0;const one=new CountryRequestIdentity(store,actor,()=>{random++;return key;}),two=new CountryRequestIdentity(store,actor,()=>{random++;return '2'.repeat(32);});
 const results=await Promise.all([one.begin(selection),two.begin(selection)]);assert.equal(results.filter(r=>r.fresh===true).length,1);assert.equal(results.filter(r=>r.fresh===false).length,1);assert.equal(random,1);for(const r of results)assert.equal(r.ticket.key,key);assert(!Object.hasOwn(store.data.get(actor),'fresh'));
 await assert.rejects(two.begin({...selection,countries:['US']}));assert.deepEqual((await one.read()).selection,selection);
 const other=new CountryRequestIdentity(store,'3'.repeat(32),()=>key);assert.equal(await other.read(),undefined);
});
test('unknown replies and attention retain original key while verified data-only terminals end only browser pending',async()=>{
 const store=atomic(),identity=new CountryRequestIdentity(store,actor,()=>key);await identity.begin(selection);
 const unknown={actor_id:actor,request_id:key,state_known:false,read_only:true,automatic_replay_allowed:false};assert.equal((await identity.observe(unknown)).key,key);
 assert.equal((await identity.observe(lookup('needs_attention'))).job,job);assert.equal(store.data.size,1);
 assert.equal(await identity.observe(lookup('succeeded')),undefined);assert.equal(store.data.size,0);
 for(const state of ['failed','succeeded']){await identity.begin(selection);assert.equal(await identity.observe(lookup(state)),undefined);}
});
test('second-tab terminal finishes its own original without resurrecting or deleting another pending',async()=>{
 const store=atomic(),one=new CountryRequestIdentity(store,actor,()=>key),two=new CountryRequestIdentity(store,actor,()=> '7'.repeat(32));const original=(await one.begin(selection)).ticket;
 await one.observe(lookup('succeeded'),original);assert.equal(store.data.size,0);assert.equal(await two.observe(lookup('succeeded'),original),undefined);assert.equal(store.data.size,0);
 await two.begin(selection);const current=structuredClone(store.data.get(actor));await assert.rejects(one.observe(lookup('succeeded'),original));assert.deepEqual(store.data.get(actor),current);
});
test('foreign acknowledgement, altered key, active policy, string booleans and false success cannot clear original',async()=>{
 const cases=[v=>v.actor_id='4'.repeat(32),v=>v.request_id='4'.repeat(32),v=>v.automatic_replay_allowed=true,v=>v.request.selection.countries=['US'],v=>delete v.request.result,v=>v.request.result.cache.activated_nginx_policy=true,v=>v.request.result.cache.published='true',v=>v.request.result.cache.original_job_id=[job],v=>v.request.result_sha256=[hash],v=>v.request.result.data_only=false];
 for(const change of cases){const store=atomic(),identity=new CountryRequestIdentity(store,actor,()=>key);await identity.begin(selection);const value=lookup('succeeded');change(value);await assert.rejects(identity.observe(value));assert.equal(store.data.get(actor).key,key);}
 const store=atomic(),identity=new CountryRequestIdentity(store,actor,()=>key),first=(await identity.begin(selection)).ticket;
 await assert.rejects(identity.accepted(first,{job_id:job,request_id:'4'.repeat(32),replayed:false,data_only:true}));assert.equal((await identity.read()).job,undefined);
 await identity.accepted(first,{job_id:job,request_id:key,replayed:false,data_only:true});await assert.rejects(identity.accepted(first,{job_id:'4'.repeat(32),request_id:key,replayed:true,data_only:true}));assert.equal((await identity.read()).job,job);
});
test('unavailable, corrupt or exhausted storage never returns a replacement ticket',async()=>{
 const unavailable={run:async()=>{throw Error('explicit storage refusal');}};await assert.rejects(new CountryRequestIdentity(unavailable,actor,()=>key).begin(selection));await assert.rejects(new IndexedCountryStorage(undefined).run(actor,true,()=>({})));
 for(const value of [null,{},[],{format:1,actor,key,selection:{...selection,source:'not accepted'}},{format:1,actor:'5'.repeat(32),key,selection},{format:1,actor,key,selection,fresh:true}]){const s=atomic();s.data.set(actor,value);const original=structuredClone(value),identity=new CountryRequestIdentity(s,actor,()=>key);await assert.rejects(identity.read());await assert.rejects(identity.begin(selection));assert.deepEqual(s.data.get(actor),original);}
 const full=atomic();for(let i=0;i<128;i++)full.data.set('unrelated-'+i,{});await assert.rejects(new CountryRequestIdentity(full,actor,()=>key).begin(selection));assert.equal(full.data.size,128);
});
test('actual component second-tab submit observes existing original and issues no automatic POST',async()=>{
 const {deps,methods,submit}=submitFixture({begin:async()=>({ticket:{key,selection},fresh:false})});await submit()(false);assert.equal(methods.filter(x=>x.method==='POST').length,0);assert.equal(methods.filter(x=>x.method==='read-original').length,1);assert.equal(deps.pending.value.key,key);
});
test('actual component durable storage failure or changed account never issues POST',async()=>{
 for(const mode of ['storage','account']){const {deps,methods,submit}=submitFixture({begin:async()=>{if(mode==='storage')throw Error('explicit storage failure');deps.current=()=>false;return{ticket:{key,selection},fresh:true};}});if(mode==='account'){const original=deps.current;deps.current=(...args)=>deps.props.actor===actor&&original(...args);deps.identity=()=>({begin:async()=>{deps.props.actor='9'.repeat(32);return{ticket:{key,selection},fresh:true};}});}await submit()(false);assert.equal(methods.filter(x=>x.method==='POST').length,0);}
});
test('actual explicit restore sends only exact original actor, key and selection to data queue',async()=>{
 const {deps,methods,submit}=submitFixture({accepted:async(original)=>({...original,job})});deps.pending.value={key,selection:structuredClone(selection)};deps.outcome.value={state_known:false};deps.selected.value=['US'];await submit()(true);const posts=methods.filter(x=>x.method==='POST');assert.equal(posts.length,1);assert.equal(posts[0].path,'/software/nginx-waf/country-data');assert.equal(posts[0].request,key);assert.deepEqual(posts[0].body,{actor_id:actor,selection});
});
test('data view stays separate from policy activation and installed-source reporting',()=>{
 const value=lookup('succeeded').request;assert.equal(readCountryDetail(value,actor,job).result.cache.activated_nginx_policy,false);assert.throws(()=>readCountryDetail(value,actor,'8'.repeat(32)));
 const component=read('web/src/WafCountryData.vue');for(const phrase of ['下载成功不表示防护已启用','未匹配所选地区','原发布任务','不是当前数据文件完整性或网站防护生效的证明'])assert(component.includes(phrase));assert(!component.includes("'/software/nginx-waf/configure'"));assert(!component.includes('localStorage'));assert(!component.includes('sessionStorage'));
 const app=read('web/src/App.vue'),parent=read('web/src/WafWorkspace.vue');assert(app.includes(':actor="securityWorkspaceScope.actor"'));assert(parent.includes("status.version==='2.6.0'&&actor"));
});
