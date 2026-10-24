import {test}from'node:test';
import assert from'node:assert/strict';
import{readFileSync}from'node:fs';
import{apacheBodyPolicySupported as supported,apacheBodyPolicyAddSite as add}from'../web/src/apacheBodyPolicy.ts';
const a='a'.repeat(32),b='b'.repeat(32),e='c'.repeat(32),read=n=>readFileSync(new URL('../'+n,import.meta.url),'utf8');
test('only actual matching2.4 installed identity enables native body draft',()=>{
 assert.equal(supported(true,'2.4.0','2.4.0'),true);
 for(const values of [[false,'2.4.0','2.4.0'],['true','2.4.0','2.4.0'],[undefined,'2.4.0','2.4.0'],[true,'2.3.0','2.4.0'],[true,'2.4.0','2.3.0'],[true,'2.4.0-compat1','2.4.0'],[true,'2.5.0','2.5.0'],[true,null,null]])assert.equal(supported(...values),false,JSON.stringify(values));
});
test('explicit selected site starts observe and preserves prior immutable draft',()=>{
 const body={engine_job_id:e,sites:[]},snapshot=structuredClone(body),sites=[{id:a,status:'running'},{id:b,status:'stopped'}];
 const out=add(body,a,sites);assert.deepEqual(body,snapshot);assert.equal(out.sites.length,1);assert.equal(out.sites[0].policy.mode,'observe');assert.equal(out.sites[0].policy.body_limit_kib,1024);
 assert.throws(()=>add(out,a,sites));assert.throws(()=>add(out,b,sites));assert.throws(()=>add(out,'../unknown',sites));assert.throws(()=>add(undefined,a,sites));assert.throws(()=>add({...body,engine_job_id:'invalid'},a,sites));
 for(const status of ['archived','queued','needs_attention',''])assert.throws(()=>add(out,b,[{id:b,status}]));
 const full={engine_job_id:e,sites:Array.from({length:64},(_,i)=>({site_id:i.toString(16).padStart(32,'0'),policy:{...out.sites[0].policy}}))};
 assert.throws(()=>add(full,a,sites));assert.equal(full.sites.length,64);
 out.sites[0].policy.mode='block';const second=add(out,b,[{id:b,status:'running'}]);second.sites[0].policy.mode='off';assert.equal(out.sites[0].policy.mode,'block');
});
test('native UI only edits drafts with fresh complete inventory; no own write endpoint',()=>{
 const view=read('web/src/ApacheBodyPolicy.vue');
 for(const text of ['apacheBodyBuildInventory(out)','known.value=false','ticket!==epoch','row.state==="ready"','apacheBodyPolicyAddSite','props.parentBusy','onBeforeUnmount','观察','缓存写入失败返回503','Apache本版不提供CC限速'])assert.ok(view.includes(text),text);
 assert.doesNotMatch(view,/"POST"|fetch\(|setInterval|\/nginx-waf|\/configure|\/install|\/update/);
 assert.match(read('web/src/WafWorkspace.vue'),/<ApacheBodyPolicy :api="api" :active="tab==='apache-body-policy'"/);
 assert.match(read('packaging/build-release.sh'),/test-apache-body-policy\.mjs/);
 const unit=read('dev/panel-apache-body-build@.service');for(const bound of ['MemoryHigh=576M','MemoryMax=640M','MemorySwapMax=0','CPUQuota=85%','TimeoutStartSec=245min'])assert.ok(unit.includes(bound),bound);
});

