// Browser policy/data boundary fixtures only; no signing, requests or activation.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import ts from '../web/node_modules/typescript/lib/typescript.js';
const read=p=>fs.readFileSync(new URL('../'+p,import.meta.url),'utf8');
const compile=source=>ts.transpileModule(source,{compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.ESNext}}).outputText;
const url=source=>'data:text/javascript;base64,'+Buffer.from(source).toString('base64');
let hashCode=compile(read('web/src/browserSHA256.ts'));
const noble=new URL('../web/node_modules/@noble/hashes/sha2.js',import.meta.url).href;
hashCode=hashCode.replaceAll('"@noble/hashes/sha2.js"',JSON.stringify(noble)).replaceAll("'@noble/hashes/sha2.js'",JSON.stringify(noble));
const hashURL=url(hashCode),identityURL=url(compile(read('web/src/wafCountryIdentity.ts')));
let policy=compile(read('web/src/wafCountryPolicy.ts'));
for(const [name,value]of [['./browserSHA256',hashURL],['./wafCountryIdentity',identityURL]])policy=policy.replaceAll("'"+name+"'",JSON.stringify(value)).replaceAll('"'+name+'"',JSON.stringify(value));
const {browserSHA256}=await import(hashURL),{countryDraftFromOriginal,countryPolicyDraftProblem,countryDataAgeDays}=await import(url(policy));
const actor='a'.repeat(32),job='b'.repeat(32),sha='c'.repeat(64);
function original(){
 const selection={action:'download',app_version:'2.6.0',app_manifest_sha256:sha,installation_sha256:sha,release:'2026-10',revision:1,data_manifest_sha256:sha,countries:['CN','US']};
 return {actor_id:actor,request:{id:job,state:'succeeded',created_at:'2026-10-29T00:00:00Z',payload_sha256:sha},selection,read_only:true,error:'',result_sha256:sha,result:{format:1,job_id:job,actor_id:actor,selection:structuredClone(selection),payload_sha256:sha,request_sha256:sha,requested_cache_plan_sha256:sha,state:'succeeded',error:'',data_only:true,automatic_replay_allowed:false,cache:{dataset:sha+'-'+browserSHA256(JSON.stringify(selection.countries)),data_manifest_sha256:sha,countries:['CN','US'],release:'2026-10',revision:1,original_job_id:job,plan_sha256:sha,prepared_at:'2026-10-29T00:00:00Z',bytes:100,networks:2,published:true,reused:false,activated_nginx_policy:false}}};
}
test('completed original data becomes only a detached disabled policy draft',()=>{
 const source=original(),before=structuredClone(source),draft=countryDraftFromOriginal(source,actor);
 assert.equal(draft.enabled,false);assert.deepEqual(draft.global,{mode:'off',list:'',countries:[]});assert.deepEqual(draft.sites,[]);
 assert.equal(draft.data.dataset,source.result.cache.dataset);
 draft.data.countries.push('ZA');assert.deepEqual(source,before);
});
test('unknown, foreign, substituted and nonterminal data cannot become a policy draft',()=>{
 for(const kind of ['foreign-actor','failed','missing-result','active-claim','substituted-hash','unpublished','changed-release']){
  const data=original();let owner=actor;
  if(kind==='foreign-actor')owner='d'.repeat(32);
  if(kind==='failed'){data.request.state=data.result.state='failed';data.error=data.result.error='original failure';}
  if(kind==='missing-result')delete data.result;
  if(kind==='active-claim')data.result.cache.activated_nginx_policy=true;
  if(kind==='substituted-hash')data.result.cache.dataset=sha+'-'+'f'.repeat(64);
  if(kind==='unpublished')data.result.cache.published=false;
  if(kind==='changed-release')data.result.cache.release='2026-09';
  assert.throws(()=>countryDraftFromOriginal(data,owner),kind);
 }
});
test('active rule drafts require prepared coverage and freshness hint retains a visible old dataset',()=>{
 const draft=countryDraftFromOriginal(original(),actor);draft.global={mode:'block',list:'deny',countries:[]};assert(countryPolicyDraftProblem(draft));
 draft.global.countries=['CN'];assert.equal(countryPolicyDraftProblem(draft),'');
 draft.sites=[{site_id:job,rule:{mode:'observe',list:'allow',countries:['DE']}}];assert(countryPolicyDraftProblem(draft));assert.equal(draft.data.release,'2026-10');
 assert.equal(countryDataAgeDays('2026-10',Date.parse('2027-02-01T00:00:00Z')),123);
 assert.equal(countryDataAgeDays('2026-13'),undefined);
});
