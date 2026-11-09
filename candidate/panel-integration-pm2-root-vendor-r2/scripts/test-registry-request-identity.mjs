import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { createHash, randomBytes } from 'node:crypto';
import ts from '../web/node_modules/typescript/lib/typescript.js';
const source=fs.readFileSync(new URL('../web/src/registryRequestIdentity.ts',import.meta.url),'utf8');
const js=ts.transpileModule(source,{compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.ESNext}}).outputText;
const {registryFingerprint,RegistryRequestIdentity}=await import('data:text/javascript;base64,'+Buffer.from(js).toString('base64'));
const actor='1'.repeat(32), other='2'.repeat(32), path='/app-registry/load-balance/install';
const body={expected_version:'1.3.0',expected_sha256:'a'.repeat(64),settings:{port:8081,password:'qa-only-secret-not-for-storage'}};
const wire=()=>JSON.stringify(body);
function fixture(){const values=new Map();let count=0;const storage={getItem:k=>values.get(k)||null,setItem:(k,v)=>values.set(k,v),removeItem:k=>values.delete(k)};const create=()=>new RegistryRequestIdentity(storage,()=>String(++count).padStart(32,'0'));const cache=create();cache.bind(actor);return {cache,create,storage,values};}
function outcome(ticket,change={}){return {app_id:ticket.app,action:ticket.action,job_id:'3'.repeat(32),provider:'panel-module',state:'running',state_known:true,version:body.expected_version,sha256:body.expected_sha256,...change};}
test('portable fingerprint agrees with independent SHA-256 including block boundaries and UTF-8',()=>{
 for(const value of ['', 'abc', '汉字 / ⚙️ / \ud800', ...Array.from({length:193},(_,i)=>'x'.repeat(i)),randomBytes(10000).toString('hex')]) assert.equal(registryFingerprint(value),createHash('sha256').update(value).digest('hex'));
 assert.throws(()=>registryFingerprint('x'.repeat(24*1024+1)));
});
test('persist-before-send, reload replay, canonical nested fields, no plaintext settings',()=>{
 const {cache,create,values}=fixture();const first=cache.begin(path,wire());
 assert(values.size===1);assert(![...values.values()].join('').includes(body.settings.password));assert(![...values.values()].join('').includes('"settings"'));
 const reordered=JSON.stringify({settings:{password:body.settings.password,port:8081},expected_sha256:body.expected_sha256,expected_version:'1.3.0'});
 assert.equal(cache.begin(path,reordered).key,first.key);
 const reloaded=create();reloaded.bind(actor,true);assert.equal(reloaded.begin(path,wire()).key,first.key);
 for(const changed of [{...body,settings:{port:8082}},{...body,expected_version:'1.4.0'}])assert.throws(()=>reloaded.begin(path,JSON.stringify(changed)),/待确认/);
 assert.throws(()=>reloaded.begin(path.replace('/install','/update'),wire()),/待确认/);
});
test('unknown and needs-attention do not retire a request; known terminal observation permits a new deliberate attempt',()=>{
 for(const state of ['unknown','queued','running','needs_attention','succeeded','failed']){
  const {cache}=fixture();const first=cache.begin(path,wire());const result=outcome(first,{state,state_known:state!=='unknown'});
  assert.equal(cache.observe(first,result),['succeeded','failed'].includes(state));
  const second=cache.begin(path,wire());assert.equal(second.key===first.key,!['succeeded','failed'].includes(state));
 }
});
test('accepted receipt remains bound, corrupted observations and late accounts fail closed',()=>{
 const {cache}=fixture();const first=cache.begin(path,wire());cache.accepted(first,{job_id:'3'.repeat(32),provider:'panel-module'});
 for(const changed of [{job_id:'4'.repeat(32)},{provider:'compose'},{state:'healthy'},{state_known:false,state:'succeeded'},{action:'update'},{version:'1.9.0'},{sha256:'b'.repeat(64)},{app_id:'nginx'}])assert.throws(()=>cache.observe(first,outcome(first,changed)));
 assert.throws(()=>cache.accepted(first,{job_id:'4'.repeat(32),provider:'panel-module'}));
 cache.clear();cache.bind(other);cache.accepted(first,{job_id:'3'.repeat(32),provider:'panel-module'});assert.equal(cache.list().length,0);
 const second=cache.begin(path,wire());assert.notEqual(second.key,first.key);
});
test('cross-account restore, corrupt storage, quota and unavailable storage never silently issue fresh requests',()=>{
 const {cache,create,values}=fixture();const first=cache.begin(path,wire());const next=create();next.bind(other,true);assert.notEqual(next.begin(path,wire()).key,first.key);
 values.set('panel-registry-pending-v1','{"format":1,"actor":"'+actor+'","pending":[{"secret":"bad"}]}');const corrupted=create();corrupted.bind(actor,true);assert.throws(()=>corrupted.begin(path,wire()),/不可读取/);
 const blocked=new RegistryRequestIdentity({getItem:()=>null,setItem:()=>{throw new Error('quota');},removeItem:()=>{}},()=> '9'.repeat(32));blocked.bind(actor);assert.throws(()=>blocked.begin(path,wire()),/不能保存/);assert.equal(blocked.list().length,0);
});
test('only exact store operations are accepted; no automatic mutation retry or forgotten unknown job',()=>{
 const {cache}=fixture();for(const bad of ['/software/load-balance/install','/app-registry/../install','/app-registry/load-balance/install?retry=1','/app-registry/load-balance/delete'])assert.throws(()=>cache.begin(bad,wire()));
 const first=cache.begin(path,wire());cache.accepted(first,{job_id:'3'.repeat(32),provider:'panel-module'});
 cache.terminalJobs([{id:'4'.repeat(32),state:'succeeded'},{id:'3'.repeat(32),state:'needs_attention'}]);assert.equal(cache.list().length,1);
 cache.terminalJobs([{id:'3'.repeat(32),state:'failed'}]);assert.equal(cache.list().length,0);
 const compose=cache.begin(path,wire());cache.accepted(compose,{job_id:'3'.repeat(32),project_id:'4'.repeat(32)});cache.terminalJobs([{id:'3'.repeat(32),state:'succeeded'}]);assert.equal(cache.list().length,1);
});
test('only an explicit verified unsubmitted closure releases an unknown request',()=>{
 const {cache}=fixture();const first=cache.begin(path,wire());
 const closed=outcome(first,{state:'closed_without_submission',state_known:true,job_id:'',provider:''});
 for(const change of [{state_known:false},{job_id:'3'.repeat(32)},{provider:'panel-module'}])assert.throws(()=>cache.observe(first,{...closed,...change}));
 assert(cache.observe(first,closed));assert.notEqual(cache.begin(path,wire()).key,first.key);
 const next=cache.begin(path,wire());cache.accepted(next,{job_id:'3'.repeat(32),provider:'panel-module'});assert.throws(()=>cache.observe(next,closed));assert.equal(cache.list().length,1);
});
