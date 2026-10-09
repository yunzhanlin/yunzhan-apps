import test from 'node:test';import assert from 'node:assert/strict';import fs from 'node:fs';
import ts from '../web/node_modules/typescript/lib/typescript.js';
const source=fs.readFileSync(new URL('../web/src/networkIDSOperations.ts',import.meta.url),'utf8');
const js=ts.transpileModule(source,{compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.ESNext}}).outputText;
const {validIDSOperation,validIDSRuleProfile}=await import('data:text/javascript;base64,'+Buffer.from(js).toString('base64'));
const fixture={id:'a'.repeat(32),action:'ids-start',input:{expected_revision:1},state:'queued',created_at:'2026-10-09T13:00:00Z',updated_at:'2026-10-09T13:00:00Z',steps:[]};
test('native receipts remain closed and acceptance is not success',()=>{
 assert(validIDSOperation(fixture));
 for(const change of [v=>v.id=[v.id],v=>v.action='shell',v=>v.capture_started=true,v=>v.state='healthy',v=>v.input.path='/etc/passwd',v=>v.input.enabled=false,v=>v.input.expected_revision=-1,v=>v.input.expected_revision=Number.MAX_SAFE_INTEGER+1,v=>v.steps=null,v=>v.steps=Array(17).fill({time:fixture.created_at,message:'bounded'}),v=>v.updated_at='2026-10-08T13:00:00Z',v=>v.state='needs-attention',v=>{v.state='succeeded';v.error='unresolved';}]){const candidate=structuredClone(fixture);change(candidate);assert(!validIDSOperation(candidate));}
 const failed={...fixture,state:'needs-attention',error:'Retained native outcome'};assert(validIDSOperation(failed));
});
test('rule selection is explicit and cannot be replaced by a path or a missing field',()=>{
 const selection={feed_id:'et-open-web-20261009',app_version:'1.2.0',app_manifest_sha256:'a'.repeat(64),rule_manifest_sha256:'b'.repeat(64)};
 for(const rule_profile of [{source:'original'},{source:'verified-feed',selection}])assert(validIDSOperation({...fixture,action:'ids-rules',input:{expected_revision:1,rule_profile}}));
 for(const choice of [null,{},[],{source:'original',selection},{source:'verified-feed'},{source:'original',path:'/etc'},{source:'verified-feed',selection:{...selection,rule_manifest_sha256:'../bad'}},{source:'verified-feed',selection:{...selection,Feed_ID:selection.feed_id}}])assert(!validIDSRuleProfile(choice));
 assert(!validIDSOperation({...fixture,action:'ids-rules',input:{expected_revision:1}}));
 assert(!validIDSOperation({...fixture,input:{expected_revision:1,rule_profile:{source:'original'}}}));
});
test('configuration and boot choices cannot be mixed with other operations',()=>{
 assert(validIDSOperation({...fixture,action:'ids-config',input:{expected_revision:1,network_interface:'lo',home_networks:['127.0.0.1/32']}}));
 assert(validIDSOperation({...fixture,action:'ids-boot',input:{expected_revision:1,enabled:false}}));
 for(const input of [{expected_revision:1},{expected_revision:1,enabled:null},{expected_revision:1,enabled:true,network_interface:'lo'}])assert(!validIDSOperation({...fixture,action:'ids-boot',input}));
 assert(!validIDSOperation({...fixture,action:'ids-config',input:{expected_revision:1,network_interface:'any',home_networks:[]}}));
});
