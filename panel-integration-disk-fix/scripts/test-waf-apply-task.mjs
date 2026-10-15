import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import ts from '../web/node_modules/typescript/lib/typescript.js';
import {wafQueuedApplyID,wafApplyTaskOutcome,wafCommittedConfiguration} from '../web/src/wafApplyTask.ts';
import {wafRecoveredApplyTicket} from '../web/src/wafApplyRecovery.ts';
import {softwareInstallState} from '../web/src/softwareState.ts';
const read=p=>readFileSync(new URL('../'+p,import.meta.url),'utf8');
const id='a'.repeat(32),kind='software_configure',engine='nginx-waf';
const job={id,target_id:engine,kind,state:'running',error:''};
test('queued receipt requires a canonical original ID, including install callbacks',()=>{
 assert.equal(wafQueuedApplyID(id),id);assert.equal(wafQueuedApplyID({job_id:id,provider:'panel-module'}),id);
 for(const value of [undefined,null,[],{},0,{job_id:7},id.toUpperCase(),id+' ',{job_id:'../wrong'},'b'.repeat(31)])assert.throws(()=>wafQueuedApplyID(value));
});
test('ordinary queued/running and succeeded have closed, bound outcomes',()=>{
 for(const engine of ['nginx-waf','apache-waf'])for(const kind of ['software_install','software_configure'])for(const state of ['queued','running','succeeded'])assert.deepEqual(wafApplyTaskOutcome(id,engine,kind,{...job,target_id:engine,kind,state}),{state:state==='succeeded'?'succeeded':'pending',detail:''});
});
test('needs-attention returns uncertainty immediately, distinct from failure/success',()=>{
 const out=wafApplyTaskOutcome(id,engine,kind,{...job,state:'needs_attention'});assert.equal(out.state,'attention');assert.match(out.detail,/保留原任务/);
 assert.deepEqual(wafApplyTaskOutcome(id,engine,kind,{...job,state:'needs_attention',error:'actual executor uncertainty'}),{state:'attention',detail:'actual executor uncertainty'});
 for(const state of ['failed','cancelled'])assert.deepEqual(wafApplyTaskOutcome(id,engine,kind,{...job,state,error:'actual failure'}),{state:'failed',detail:'actual failure'});
});
test('wrong jobs, target, kind, missing errors and unknown success-like states fail closed',()=>{
 for(const change of [{id:'b'.repeat(32)},{target_id:'system-hardening'},{kind:'software_update'},{error:undefined},{error:'x'.repeat(32769)},{state:'healthy'},{state:'ready'},{state:1}])assert.throws(()=>wafApplyTaskOutcome(id,engine,kind,{...job,...change}));
 for(const value of [null,[],{},'succeeded'])assert.throws(()=>wafApplyTaskOutcome(id,engine,kind,value));
 assert.throws(()=>wafApplyTaskOutcome('../wrong',engine,kind,job));assert.throws(()=>wafApplyTaskOutcome(id,'other',kind,job));
});
test('actual task parser rejects private/unknown fields, foreign prototypes and UTF8 oversize errors',()=>{
 for(const value of [{...job,settings:{private:'not a task receipt'}},{...job,payload:'private'},{...job,steps:[]},{...job,unexpected:true},Object.assign(Object.create({}),job),{...job,error:'汉'.repeat(10923)}])assert.throws(()=>wafApplyTaskOutcome(id,engine,kind,value));
 assert.equal(wafApplyTaskOutcome(id,engine,kind,{...job,error:'汉'.repeat(10922)}).state,'pending');
 assert.equal(wafApplyTaskOutcome(id,engine,kind,Object.assign(Object.create(null),job)).state,'pending');
});
test('the actual workspace keeps the original queued ticket and rechecks it without a new write',()=>{
 const source=read('web/src/WafWorkspace.vue');
 assert.match(source,/const pendingApply = ref/);assert.match(source,/if \(!ticket\)/);assert.match(source,/if \(!ticket\.job\)/);
 assert.match(source,/ticket\.key/);assert.match(source,/wafQueuedApplyID/);assert.match(source,/wafApplyTaskOutcome\(ticket\.job, engine, ticket\.kind, job\)/);
 assert.match(source,/outcome\.state === "attention"\) throw/);assert.match(source,/outcome\.state === "failed"[\s\S]*?pendingApply\.value = undefined/);
 assert.match(source,/核对原任务/);assert.match(source,/原任务结果尚未确认/);assert.match(source,/当前实际防护状态未核实/);
 assert.match(read('packaging/build-release.sh'),/test-waf-apply-task\.mjs/);
});

// Execute the actual component function, not a separately implemented model.
// This is host control-flow evidence, not a browser or installed-engine proof.
const source=read('web/src/WafWorkspace.vue');
const applySource=source.slice(source.indexOf('async function apply()'),source.indexOf('function discard()'));
const applyJS=ts.transpileModule(applySource,{compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.ESNext}}).outputText;
function harness(options={}) {
 const cfg={value:{policy:{mode:'block',revision:7},fixture:'original'}},status={value:{installed:options.installed!==false,enabled:options.installed!==false,healthy:options.installed!==false}},
  busy={value:false},error={value:''},saved={value:''},pendingApply={value:undefined},applied={value:undefined};
 const requests=[],installs=[],events=[];let keys=0,history=0,reads=0;
 const bindings={cfg,status,busy,error,saved,pendingApply,applied,recoveredApplyNote:{value:''},disposed:!!options.disposed,engine,engineName:'Nginx',softwareInstallState,installState:{get value(){return softwareInstallState(status.value?{id:engine,...status.value}:undefined);}},
  clone:v=>JSON.parse(JSON.stringify(v)),newID:()=>String(++keys).padStart(32,'0'),endpoint:v=>`/software/${engine}/${v}`,
  wafApplyTaskOutcome,wafQueuedApplyID,wafCommittedConfiguration,setTimeout:resolve=>resolve(),
  validate:async()=>{events.push('validate');if(options.validate)await options.validate(bindings);},
  props:{api:async(path,method,body,key)=>{
   requests.push({path,method,body,key});
   if(method==='POST'){
    assert(pendingApply.value,'original ticket exists before submission');events.push('post');
    if(options.post)return options.post(requests.length,bindings);
    return {job_id:id};
   }
   assert.equal(path,`/software/${engine}/jobs/${id}`,'only read the original WAF task endpoint, never global audit');
   reads++;events.push('read');
   return options.read ? options.read(reads,bindings) : {...job,state:'succeeded'};
  },onInstall:async(target,settings)=>{
   installs.push({target,settings});assert(pendingApply.value);events.push('install');
   return options.install ? options.install(bindings) : id;
  }},
  loadConfig:async()=>{events.push('config');status.value={installed:true,enabled:true,healthy:true};applied.value=structuredClone(pendingApply.value.settings);applied.value.policy.revision++;if(options.load)await options.load(bindings);},
  refreshHistory:async()=>{history++;events.push('history');},refreshReport:async()=>{events.push('report');},
  refreshBodyReport:async()=>{},refreshBodyArchives:async()=>{},refreshBodyRotation:async()=>{}};
 // A dynamic lexical fixture keeps `disposed` observable across an await,
 // just like the actual component's unmount hook, not a copied boolean.
 const actual=new Function('bindings','with (bindings) { '+applyJS+'\nreturn apply; }')(bindings);
 const apply=()=>actual();
 return {apply,bindings,requests,installs,events,get keys(){return keys;},get history(){return history;},get reads(){return reads;}};
}

test('actual completed task cannot certify current protection from an explicitly unknown install record',async()=>{
 const h=harness({load:b=>{b.status.value.state_unknown=true;}});
 await h.apply();
 assert.equal(h.bindings.saved.value,'');assert.match(h.bindings.error.value,/安装状态无法核对/);
 assert.equal(h.bindings.pendingApply.value.job,id);
 const reads=h.reads,posts=h.requests.filter(r=>r.method==='POST').length;
 await h.apply();assert.equal(h.reads,reads);assert.equal(h.requests.filter(r=>r.method==='POST').length,posts);
});
test('actual apply retains a lost POST reply and manually reuses exact key and configuration',async()=>{
 let writes=0;const h=harness({post:()=>{if(++writes===1)throw new Error('lost actual reply');return {job_id:id};}});
 await h.apply();assert.match(h.bindings.error.value,/lost actual reply/);assert.equal(h.requests.length,1);
 const original=h.bindings.pendingApply.value;assert(original&&!original.job);assert.equal(h.keys,1);
 h.bindings.cfg.value.fixture='different later draft';await h.apply();
 const posts=h.requests.filter(r=>r.method==='POST');assert.equal(posts.length,2);assert.equal(posts[0].key,posts[1].key);
 assert.deepEqual(posts[0].body,posts[1].body);assert.equal(posts[1].body.settings.fixture,'original');assert.equal(h.keys,1);
 assert.equal(h.events.filter(e=>e==='validate').length,1);assert.equal(h.bindings.pendingApply.value,undefined);assert.match(h.bindings.saved.value,/实际生效配置/);
});
test('actual known-job read failure keeps the ticket and recheck never writes again',async()=>{
 const h=harness({read:n=>{if(n===1)throw new Error('network read failure');return {...job,state:'succeeded'};}});
 await h.apply();assert.equal(h.bindings.pendingApply.value.job,id);assert.equal(h.bindings.saved.value,'');
 await h.apply();assert.equal(h.requests.filter(r=>r.method==='POST').length,1);assert.equal(h.keys,1);assert.equal(h.reads,2);
});
test('actual recovered install and configure tickets read the same known job without validation, callback, key or POST',async()=>{
 for(const kind of ['software_install','software_configure']){
  const settings={profile:'balanced',rate_per_second:20,policy:{schema_version:2,revision:7,mode:'off',cc_enabled:false,burst:60,groups:{},lists:{},rules:[],sites:[],cc_rules:[]}};
  const request={id,target_id:engine,kind,state:'queued',created_at:'2026-10-11T00:00:00Z',request_sha256:'a'.repeat(64),signed_install_binding:kind==='software_install'};
  const h=harness({installed:false,read:n=>{if(n===1)throw new Error('original read unavailable');return {...job,kind,state:'succeeded'};}});
  const original=wafRecoveredApplyTicket(engine,{request,error:'',settings,read_only:true});h.bindings.pendingApply.value=original;
  h.bindings.cfg.value={policy:{revision:90,mode:'block'},fixture:'new unrelated draft'};
  await h.apply();assert.equal(h.bindings.pendingApply.value,original);assert.equal(h.bindings.saved.value,'');
  await h.apply();assert.equal(h.requests.length,2);assert(h.requests.every(r=>!r.method&&r.path===`/software/${engine}/jobs/${id}`));
  assert.equal(h.installs.length,0);assert.equal(h.keys,0);assert(!h.events.includes('validate'));assert.equal(h.bindings.pendingApply.value,undefined);assert.match(h.bindings.saved.value,/实际生效配置/);
  assert.equal(original.settings.policy.revision,7);assert.equal(original.settings.policy.mode,'off');
 }
});
test('actual needs-attention, wrong task and unknown state stop immediately and retain original job',async()=>{
 for(const result of [{...job,state:'needs_attention',error:'actual uncertain result'},{...job,id:'b'.repeat(32),state:'succeeded'},{...job,state:'ready'},{...job,state:'succeeded',payload:'not a closed outcome'},{...job,state:'succeeded',error:'汉'.repeat(10923)}]){
  const h=harness({read:()=>result});await h.apply();assert.equal(h.reads,1);assert.equal(h.bindings.pendingApply.value.job,id);
  assert.equal(h.bindings.saved.value,'');assert(h.bindings.error.value);assert(!h.events.includes('config'));
  await h.apply();assert.equal(h.requests.filter(r=>r.method==='POST').length,1);assert.equal(h.reads,2);
 }
});
test('actual terminal failure permits a fresh deliberate request, never an automatic retry',async()=>{
 for(const state of ['failed','cancelled']){
  const h=harness({read:()=>({...job,state,error:'actual native rejection'})});await h.apply();
  assert.equal(h.bindings.pendingApply.value,undefined);assert.equal(h.keys,1);assert.equal(h.requests.filter(r=>r.method==='POST').length,1);
  assert.equal(h.bindings.error.value,'actual native rejection');assert.equal(h.bindings.saved.value,'');
 }
});
test('actual success requires a fresh healthy configuration; unavailable configuration retains original job',async()=>{
 const unhealthy=harness({load:b=>{b.status.value.healthy=false;b.status.value.detail='actual fingerprint mismatch';}});await unhealthy.apply();
 assert.equal(unhealthy.bindings.saved.value,'');assert.match(unhealthy.bindings.error.value,/actual fingerprint mismatch/);
 const failed=harness({load:()=>{throw new Error('configuration read unavailable');}});await failed.apply();
 assert.equal(failed.bindings.pendingApply.value.job,id);assert.equal(failed.bindings.saved.value,'');assert.match(failed.bindings.error.value,/configuration read unavailable/);
});
test('actual success statement is refused if another healthy configuration supersedes this task',async()=>{
 for(const alter of [b=>{b.applied.value.policy.revision++;},b=>{b.applied.value.policy.mode='observe';},b=>{b.applied.value.fixture='some other administrator';}]){
  const h=harness({load:alter});await h.apply();assert.equal(h.bindings.status.value.healthy,true);
  assert.equal(h.bindings.pendingApply.value,undefined);assert.equal(h.bindings.saved.value,'');assert.match(h.bindings.error.value,/不再与本次提交一致/);
  assert.equal(h.requests.filter(r=>r.method==='POST').length,1);assert.equal(h.keys,1);
 }
});
test('committed configuration binds the exact next revision and all normalized policy data',()=>{
 const wanted={profile:'balanced',rate_per_second:20,policy:{revision:7,mode:'block',lists:{ip_allow:[],ip_deny:[{id:'x',value:'127.0.0.1'}]}},body:{engine_job_id:id,sites:[]},trusted_proxy:{enabled:false},body_log_rotation:{enabled:false},body_log_retention:{enabled:false}};
 const committed=structuredClone(wanted);committed.policy.revision=8;
 assert.equal(wafCommittedConfiguration(wanted,committed),true);
 const reordered={body_log_retention:committed.body_log_retention,body_log_rotation:committed.body_log_rotation,trusted_proxy:committed.trusted_proxy,body:committed.body,policy:{lists:committed.policy.lists,mode:'block',revision:8},rate_per_second:20,profile:'balanced'};
 assert.equal(wafCommittedConfiguration(wanted,reordered),true);
 for(const mutation of [v=>{v.policy.revision=7;},v=>{v.policy.revision=9;},v=>{v.policy.mode='off';},v=>{v.body.engine_job_id='b'.repeat(32);},v=>{v.trusted_proxy.enabled=true;},v=>{v.body_log_rotation.enabled=true;},v=>{v.body_log_retention.enabled=true;},v=>{v.policy.lists.ip_deny[0].value='::1';},v=>{v.extra='unknown';}]){
  const different=structuredClone(committed);mutation(different);assert.equal(wafCommittedConfiguration(wanted,different),false);
 }
 const absent={profile:'balanced',rate_per_second:20,policy:{revision:7,mode:'block'}};
 const preserved={...structuredClone(absent),policy:{revision:8,mode:'block'},body:committed.body,trusted_proxy:committed.trusted_proxy,body_log_rotation:committed.body_log_rotation,body_log_retention:committed.body_log_retention};
 assert.equal(wafCommittedConfiguration(absent,preserved),true,'independent omissions retain their executor-defined meaning');
});
test('unknown, oversized, non-JSON, deep and unsafe revisions never prove a committed configuration',()=>{
 for(const value of [undefined,null,[],{}, {policy:{revision:-1}}, {policy:{revision:1.5}}, {policy:{revision:Number.MAX_SAFE_INTEGER}}, {policy:{revision:NaN}}, {policy:{revision:Infinity}}])assert.equal(wafCommittedConfiguration(value,{policy:{revision:2}}),false);
 for(const field of [undefined,()=>{},NaN,Infinity,new Date(),Array(2),'x'.repeat(130*1024),Array(16001).fill(1)]){
  const wanted={policy:{revision:1},extra:field},current={policy:{revision:2},extra:field};assert.equal(wafCommittedConfiguration(wanted,current),false);
 }
 let deep={};for(let n=0;n<40;n++)deep={child:deep};assert.equal(wafCommittedConfiguration({policy:{revision:1},extra:deep},{policy:{revision:2},extra:deep}),false);
 const cycle={};cycle.child=cycle;assert.equal(wafCommittedConfiguration({policy:{revision:1},extra:cycle},{policy:{revision:2},extra:cycle}),false);
});
test('actual polling deadline keeps a known job for explicit read-only recheck',async()=>{
 const h=harness({read:()=>job});await h.apply();assert.equal(h.reads,120);assert.equal(h.bindings.pendingApply.value.job,id);
 assert.equal(h.bindings.saved.value,'');assert.match(h.bindings.error.value,/原任务结果尚未确认/);
 await h.apply();assert.equal(h.requests.filter(r=>r.method==='POST').length,1);assert.equal(h.reads,240);assert.equal(h.keys,1);
});
test('actual rejected validation and disposed views cannot submit a configuration',async()=>{
 const bad=harness({validate:()=>{throw new Error('actual invalid draft');}});await bad.apply();assert.equal(bad.keys,0);assert.equal(bad.requests.length,0);
 const gone=harness({disposed:true});await gone.apply();assert.equal(gone.events.length,0);assert.equal(gone.requests.length,0);
 const during=harness({validate:b=>{b.disposed=true;}});await during.apply();assert.equal(during.keys,0);assert.equal(during.requests.length,0);
});
test('actual install callback retains immutable settings after a lost result without falling into configure',async()=>{
 let calls=0;const h=harness({installed:false,install:()=>{if(++calls===1)throw new Error('lost signed-store callback');return id;},read:()=>({...job,kind:'software_install',state:'succeeded'})});
 await h.apply();assert.equal(h.bindings.pendingApply.value.kind,'software_install');h.bindings.cfg.value.fixture='changed';h.bindings.status.value.installed=true;
 await h.apply();assert.equal(h.installs.length,2);assert.deepEqual(h.installs[0],h.installs[1]);assert.equal(h.requests.filter(r=>r.method==='POST').length,0);assert.equal(h.keys,1);
});
test('actual metadata-default reset retains visible independent body and log policies without mutation',()=>{
 const body={engine_job_id:id,sites:[{site_id:'b'.repeat(32),policy:{mode:'block'}}]},rotation={enabled:true,rotate_mib:16,max_age_minutes:60},retention={enabled:true,days:30};
 const previous={policy:{revision:7,mode:'off'},body,body_log_rotation:rotation,body_log_retention:retention,trusted_proxy:{enabled:true}},before=JSON.stringify(previous);
 const bindings={cfg:{value:undefined},defaults:{value:{policy:{revision:0,mode:'block',lists:{},sites:[],rules:[]}}},applied:{value:previous},saved:{value:''},preview:{value:'old'},clone:v=>JSON.parse(JSON.stringify(v)),disabledTrustedProxy:()=>({enabled:false})};
 const reset=source.slice(source.indexOf('function restoreDraft()'),source.indexOf('function addSite()'));
 const js=ts.transpileModule(reset,{compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.ESNext}}).outputText;
 new Function('bindings','with (bindings) { '+js+'\nreturn restoreDraft; }')(bindings)();
 assert.equal(JSON.stringify(previous),before);assert.equal(bindings.cfg.value.policy.revision,7);assert.equal(bindings.cfg.value.policy.mode,'off');assert.equal(bindings.cfg.value.trusted_proxy.enabled,false);
 for(const key of ['body','body_log_rotation','body_log_retention']){assert.deepEqual(bindings.cfg.value[key],previous[key]);assert.notEqual(bindings.cfg.value[key],previous[key]);}
 assert.match(bindings.saved.value,/请求体引擎、网站策略和日志策略保留/);assert.match(bindings.saved.value,/尚未应用/);assert.equal(bindings.preview.value,'');
 assert.doesNotMatch(source,/Apache 当前为独立请求元数据防护，不包含原生请求体引擎/);
});
