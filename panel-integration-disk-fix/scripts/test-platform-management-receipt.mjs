import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {createHash} from 'node:crypto';
import ts from '../web/node_modules/typescript/lib/typescript.js';
import {isPlatformMutation,platformObservation,platformMutationReplyMatches,platformMutationNeedsRead,platformReadKnown,platformActionBody,platformHostSnapshotSHA} from '../web/src/platformManagementReceipt.ts';
const token='1'.repeat(64), tokenID=createHash('sha256').update(token).digest('hex'), now=new Date().toISOString().replace(/\.\d{3}Z$/,'Z');
const hostList={hosts:[{id:'owned-host',url:'https://owned.example.invalid',expected_sha:'a'.repeat(64),healthy:false,telemetry_complete:false,error:'HTTPS unavailable'}],checked_at:now,scope:'only communication'};
const tokenList={tokens:[{token_id:tokenID,created_at:now,scope:'health-read-only'}],total:1,limit:128,read_only:true,scope:'public identifiers only'};
const replies={add:{id:'owned-host',url:'https://owned.example.invalid',expected_sha:'a'.repeat(64)},remove:{removed:'owned-host',already_absent:false},'issue-token':{token,token_id:tokenID,scope:'health-read-only',endpoint:'/api/platform/agent'},'revoke-token':{revoked:true,token_id:tokenID,already_absent:false}};
test('all mutation receipts bind exact public identities without retaining credentials',async()=>{
 for(const action of ['add','remove','issue-token','revoke-token']){
  assert(isPlatformMutation(action));const observation=await platformObservation(action,{resource_id:'owned-host',url:'https://owned.example.invalid',token});
  assert(!JSON.stringify(observation).includes(token));assert(await platformMutationReplyMatches(observation,replies[action]));
  for(const bad of [null,[],{},Object.create(replies[action]),{...replies[action],password:'secret'},{...replies[action],foreign:true}])assert(!await platformMutationReplyMatches(observation,bad));
  assert(platformMutationNeedsRead(observation,action));assert(!platformMutationNeedsRead(observation,'run'));assert(!platformMutationNeedsRead(observation,'token-list'));
 }
 const issue=await platformObservation('issue-token',{});assert(!await platformMutationReplyMatches(issue,{...replies['issue-token'],token_id:'f'.repeat(64)}));
 const bad=await platformObservation('add',{resource_id:'foreign secret',url:'https://user:OWNED-SECRET@example.invalid',token:'malformed secret'});assert.equal(bad.address,'');assert.equal(bad.tokenID,'');assert.equal(bad.resourceID,'');assert(!JSON.stringify(bad).includes('SECRET'));
});
test('only complete real readonly inventories can clear uncertainty',()=>{
 assert(platformReadKnown('run',hostList));assert(platformReadKnown('token-list',tokenList));assert(platformReadKnown('token-list',{...tokenList,tokens:[],total:0}));
 for(const bad of [null,{},[],{...tokenList,total:0},{...tokenList,limit:129},{...tokenList,read_only:false},{...tokenList,tokens:[...tokenList.tokens,...tokenList.tokens],total:2},{...tokenList,tokens:[{...tokenList.tokens[0],token}]},{...tokenList,tokens:[{...tokenList.tokens[0],created_at:'invalid'}]}])assert(!platformReadKnown('token-list',bad));
 // Shape validation is not a SQLite lookup: any valid SHA-256-shaped public
 // identity is accepted. Actual existence and revocation remain Core checks.
 assert(platformReadKnown('token-list',{...tokenList,tokens:[{...tokenList.tokens[0],token_id:token}]}));
 for(const bad of [{...hostList,hosts:[{...hostList.hosts[0],healthy:true}]},{...hostList,hosts:[{...hostList.hosts[0],report:{}}]},{...hostList,hosts:[...hostList.hosts,...hostList.hosts]},{...hostList,checked_at:'invalid'}])assert(!platformReadKnown('run',bad));
});
const source=readFileSync(new URL('../web/src/AppModuleManager.vue',import.meta.url),'utf8');
const js=ts.transpileModule(source.slice(source.indexOf('async function execute('),source.indexOf('async function reviewRemoteTicket(')),{compilerOptions:{target:ts.ScriptTarget.ES2022}}).outputText;
test('actual component binds acknowledgements, blocks blind replay, clears token and focuses mobile error',async()=>{
 for(const action of ['add','remove','issue-token','revoke-token'])for(const mode of ['success','refused','lost','foreign','access-revoked',...(['add','remove'].includes(action)?['refresh-failed','refresh-corrupt']:[])]){
  const calls=[],notices=[],focus=[];const body={resource_id:'owned-host',url:'https://owned.example.invalid',token};
  const bindings={definition:{value:{id:'platform-ops',actions:['run','token-list','add','remove','issue-token','revoke-token'],fields:[{key:'token',kind:'password'}]}},selectedPlanID:{value:'owned-host'},installedUnknown:{value:false},busy:{value:false},visible:{value:true},error:{value:''},form:{value:{...body}},report:{value:hostList},idsAccessGeneration:1,integrityModule:{value:false},canExecutePHP:()=>true,isUserMutation:()=>false,userMutationNeedsRead:()=>false,platformMutationObservation:{value:undefined},isPlatformMutation,platformObservation,platformMutationReplyMatches,platformMutationNeedsRead,platformReadKnown,inputBody:()=>({...body}),nextTick:async()=>{},userErrorAnchor:{value:{scrollIntoView:v=>focus.push(['scroll',v]),focus:v=>focus.push(['focus',v])}},ElMessage:{info:()=>{},success:v=>notices.push(v)},setReport:v=>{bindings.report.value=v;},clearWriteOnlyFields:()=>{bindings.form.value.token='';},props:{api:async(path,method,incoming)=>{
   calls.push(path);assert.equal(method,'POST');
   if(path.endsWith('/'+action)){
    assert.deepEqual(incoming,body);if(mode==='refused'||mode==='lost')throw Error(mode==='refused'?'原记录与审计未共同提交':'network reply unavailable');
    if(mode==='access-revoked')bindings.idsAccessGeneration++;
    return mode==='foreign'?{...replies[action],foreign:true}:replies[action];
   }
   assert(path.endsWith('/run')||path.endsWith('/token-list'));
   if(mode==='refresh-failed'&&calls.length===2)throw Error('readonly refresh failed');
   if(mode==='refresh-corrupt')return {hosts:[]};
   return path.endsWith('/run')?structuredClone(hostList):structuredClone(tokenList);
  }}};
  const execute=new Function('bindings','with(bindings){'+js+';return execute;}')(bindings);await execute(action);assert.equal(bindings.busy.value,false);
  if(mode==='access-revoked'){assert.equal(calls.length,1);assert.equal(notices.length,0);assert.equal(bindings.platformMutationObservation.value,undefined);continue;}
  assert.equal(bindings.form.value.token,'');
  if(mode==='success'){assert.equal(bindings.platformMutationObservation.value.state,'acknowledged');assert.equal(notices.length,1);assert.equal(calls.length,['add','remove'].includes(action)?2:1);assert.equal(focus.length,0);continue;}
  const committed=mode.startsWith('refresh-');assert.equal(bindings.platformMutationObservation.value.state,committed?'refresh_failed':'unverified');assert.equal(notices.length,committed?1:0);assert.equal(focus.length,2);assert(!JSON.stringify(bindings.platformMutationObservation.value).includes(token));
  const count=calls.length;await execute(action);assert.equal(calls.length,count,'blind write repeated');
  const required=bindings.platformMutationObservation.value.requiredRead;
  if(required==='token-list'){await execute('run');assert.notEqual(bindings.platformMutationObservation.value,undefined,'wrong inventory unlocked token write');}
  await execute(required);
  if(mode==='refresh-corrupt')assert.notEqual(bindings.platformMutationObservation.value,undefined,'corrupt inventory unlocked writes');else assert.equal(bindings.platformMutationObservation.value,undefined,'valid explicit inventory did not unlock writes');
 }
});
test('actual selection and actual input body bind host snapshots to selected identity only',()=>{
 const compile=(start,end)=>ts.transpileModule(source.slice(source.indexOf(start),source.indexOf(end)),{compilerOptions:{target:ts.ScriptTarget.ES2022}}).outputText;
 const bindings={definition:{value:{id:'platform-ops',fields:[{key:'resource_id'},{key:'url'},{key:'token'},{key:'token_id'},{key:'expected_sha'}]}},selectedPlanID:{value:'stale-host'},form:{value:{resource_id:'stale-host',token:'secret',token_id:'b'.repeat(64),expected_sha:'b'.repeat(64)}},integrityModule:{value:false},activeTab:{value:''},workspace:{value:[{id:'hosts'},{id:'host'},{id:'tokens'}]},clearWriteOnlyFields:()=>{bindings.form.value.token='';},platformActionBody,ElMessage:{info:()=>assert.fail('selection toast would obscure mobile error')}};
 const selected=new Function('bindings','with(bindings){'+compile('function selected(', 'function inputBody(')+';return selected;}')(bindings);
 const inputBody=new Function('bindings','with(bindings){'+compile('function inputBody(', 'async function reviewSelectedRemoteBackup(')+';return inputBody;}')(bindings);
 selected(hostList.hosts[0]);assert.equal(bindings.activeTab.value,'host');assert.equal(bindings.form.value.resource_id,'owned-host');assert.equal(bindings.selectedPlanID.value,'owned-host');assert.equal(platformHostSnapshotSHA(bindings.form.value,bindings.selectedPlanID.value),'a'.repeat(64));
 bindings.form.value.token=token;assert.deepEqual(inputBody('add'),{resource_id:'owned-host',url:'https://owned.example.invalid',token,expected_sha:'a'.repeat(64)});
 bindings.form.value.resource_id='new-host';assert.equal(platformHostSnapshotSHA(bindings.form.value,bindings.selectedPlanID.value),'');assert.deepEqual(inputBody('add'),{resource_id:'new-host',url:'https://owned.example.invalid',token});assert.deepEqual(inputBody('remove'),{resource_id:'new-host'});
 for(const action of ['run','token-list','issue-token'])assert.deepEqual(inputBody(action),{});
 bindings.form.value.resource_id='owned-host';assert.deepEqual(inputBody('remove'),{resource_id:'owned-host',expected_sha:'a'.repeat(64)});
 selected(tokenList.tokens[0]);assert.equal(bindings.activeTab.value,'tokens');assert.equal(bindings.selectedPlanID.value,'');assert.equal(bindings.form.value.resource_id,'');assert.equal(bindings.form.value.token,'');assert.equal(bindings.form.value.expected_sha,'');assert.deepEqual(inputBody('revoke-token'),{token_id:tokenID});
});
test('signed interface provides selectable token IDs, readonly bound host SHA and only action body keys',()=>{
 assert.match(source,/platformMutationNeedsRead\(platformMutationObservation,action\)/);assert.match(source,/只读刷新授权清单/);assert.match(source,/platformActionBody\(action,form.value,selectedPlanID.value\)/);assert.match(source,/platformHostSnapshotSHA\(form,selectedPlanID\)/);
 const workspace=readFileSync(new URL('../internal/core/app_module_workspace.go',import.meta.url),'utf8');assert.match(workspace,/\[\]string\{"resource_id", "url", "token", "expected_sha"\}/);
 const report=readFileSync(new URL('../web/src/AppModuleReport.vue',import.meta.url),'utf8');assert.match(report,/'tokens'/);assert.match(report,/授权标识（非访问令牌）/);assert.match(report,/:label="reportLabel\(column\)"/);assert.match(report,/HTTPS 与健康协议通过/);assert.match(source,/移除主机/);assert.match(source,/登记或更新主机/);
});
