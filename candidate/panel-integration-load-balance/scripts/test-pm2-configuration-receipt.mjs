import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import ts from '../web/node_modules/typescript/lib/typescript.js';
import {newPM2ConfigurationID,pm2ConfigurationRecord,pm2ConfigurationFields,pm2ConfigurationReplyMatches,pm2ConfigurationReadConfirms,pm2ConfigurationAbsentMatches} from '../web/src/pm2Configuration.ts';
const sample={resource_id:'owned-project',site_id:'a'.repeat(32),pm2_operation_id:'b'.repeat(32),expected_sha:'c'.repeat(64),state:'committed',previous_revision:7,next_revision:8,created_at:'2026-11-01T07:00:00Z',previous_running:true,previous_boot_enabled:true,automatic_replay:false};
test('configuration identity and terminal acknowledgement exclude secrets and foreign records',()=>{
 assert(pm2ConfigurationRecord(sample));
 assert.deepEqual(pm2ConfigurationFields(sample),{resource_id:sample.resource_id,pm2_operation_id:sample.pm2_operation_id,expected_sha:sample.expected_sha,confirm:''});
 const ticket={appID:sample.resource_id,operationID:sample.pm2_operation_id};
 assert(pm2ConfigurationReplyMatches(ticket,{ok:true,configuration_transaction:sample}));
 for(const patch of [{resource_id:null},{resource_id:'foreign/app'},{site_id:'foreign'},{pm2_operation_id:'bad'},{expected_sha:'bad'},{state:'success'},{previous_revision:0},{next_revision:7},{next_revision:Number.MAX_SAFE_INTEGER+1},{created_at:'bad'},{previous_running:1},{automatic_replay:true},{environment_cipher:'secret'},{before:'secret'},{after:'secret'}])assert(!pm2ConfigurationRecord({...sample,...patch}),JSON.stringify(patch));
 for(const value of [null,{},[],Object.create(sample)])assert(!pm2ConfigurationRecord(value));
 for(const patch of [{resource_id:'another-project'},{pm2_operation_id:'d'.repeat(32)},{state:'rolled_back'},{state:'needs_attention'}])assert(!pm2ConfigurationReplyMatches(ticket,{ok:true,configuration_transaction:{...sample,...patch}}));
});
test('only the exact original complete terminal observation releases an uncertain submission',()=>{
 const ticket={appID:sample.resource_id,operationID:sample.pm2_operation_id};
 for(const state of ['committed','rolled_back','recovered_stopped'])assert(pm2ConfigurationReadConfirms(ticket,{configuration_inventory_complete:true,configuration_transactions:[{...sample,state}]}));
 for(const value of [{configuration_transactions:[sample]},{configuration_inventory_complete:true,configuration_transactions:[]},{configuration_inventory_complete:true,configuration_transactions:[sample,sample]},{configuration_inventory_complete:true,configuration_transactions:[{...sample,state:'needs_attention'}]},{configuration_inventory_complete:true,configuration_transactions:[{...sample,resource_id:'other-project'}]}])assert(!pm2ConfigurationReadConfirms(ticket,value));
});
const source=readFileSync(new URL('../web/src/AppModuleManager.vue',import.meta.url),'utf8');
const executeSource=source.slice(source.indexOf('async function execute('),source.indexOf('async function reviewRemoteTicket('));
const guardSource=source.slice(source.indexOf('function canExecutePHP('),source.indexOf('const integrityModule'));
const jsSource=ts.transpileModule(guardSource+'\n'+executeSource,{compilerOptions:{target:ts.ScriptTarget.ES2022}}).outputText;
test('actual component sends one nonce, retains uncertain outcomes, clears write-only values and observes before another save',async()=>{
 for(const mode of ['success','lost-reply','refused','foreign-reply','refresh-failed','refresh-corrupt','not-accepted']){
  const calls=[];const ticket={appID:sample.resource_id,operationID:''};
  const body={resource_id:sample.resource_id,expected_revision:7,memory_mb:192,environment_patch:{TOKEN:'FIXTURE-WRITE-ONLY-SECRET'}};
  const bindings={definition:{value:{id:'pm2-manager',actions:['run','update','configuration','cancel-configuration-request'],fields:[{key:'environment_patch',kind:'secret-json'}]}},installedUnknown:{value:false},busy:{value:false},visible:{value:true},error:{value:''},form:{value:{...body}},report:{value:{}},selectedPlanID:{value:sample.resource_id},pm2ConfigurationObservation:{value:undefined},pm2ConfigurationAbsent:{value:false},integrityModule:{value:false},activeTab:{value:'control'},idsAccessGeneration:1,newPM2ConfigurationID,pm2ConfigurationReplyMatches,pm2ConfigurationReadConfirms,pm2ConfigurationAbsentMatches,inputBody:action=>action==='update'?structuredClone(body):action==='cancel-configuration-request'?{resource_id:bindings.form.value.resource_id,pm2_operation_id:bindings.form.value.pm2_operation_id,confirm:bindings.form.value.confirm}:{},ElMessage:{info:()=>{},success:()=>{}},setReport:value=>{bindings.report.value=value;},clearWriteOnlyFields:()=>{bindings.form.value.environment_patch='';},props:{api:async(path,method,incoming)=>{
   calls.push({path,method,incoming:structuredClone(incoming)});
   if(path.endsWith('/update')){
    assert.match(incoming.pm2_operation_id,/^[a-f0-9]{32}$/);ticket.operationID=incoming.pm2_operation_id;
    if(mode==='lost-reply'||mode==='refused'||mode==='not-accepted')throw Error(mode);
    return {ok:true,configuration_transaction:{...sample,pm2_operation_id:mode==='foreign-reply'?'d'.repeat(32):ticket.operationID}};
   }
   if(path.endsWith('/cancel-configuration-request'))return {configuration_inventory_complete:true,configuration_transactions:[{resource_id:ticket.appID,pm2_operation_id:ticket.operationID,expected_sha:'e'.repeat(64),state:'cancelled_before_publication',created_at:sample.created_at,automatic_replay:false}],request_cancelled:true};
   if(mode==='not-accepted')return {configuration_inventory_complete:true,configuration_transactions:[],selected_operation_absent:true,resource_id:ticket.appID,pm2_operation_id:ticket.operationID,automatic_replay:false};
   if(mode==='refresh-failed'&&calls.length===2)throw Error('readonly list unavailable');
   return mode==='refresh-corrupt'?{configuration_inventory_complete:true,configuration_transactions:[{...sample,state:'needs_attention'}]}:{apps:[{app:{id:sample.resource_id,revision:8}}],configuration_inventory_complete:true,configuration_transactions:[{...sample,pm2_operation_id:ticket.operationID}]};
  }}};
  const functions=new Function('bindings','with(bindings){'+jsSource+';return {execute,cancelUnacceptedPM2Configuration};}')(bindings);const execute=functions.execute;
  await execute('update');assert.equal(bindings.busy.value,false);assert.equal(bindings.form.value.environment_patch,'');
  if(mode==='success'){assert.equal(calls.length,2,bindings.error.value);assert.equal(bindings.pm2ConfigurationObservation.value,undefined);continue;}
  assert.deepEqual(bindings.pm2ConfigurationObservation.value,ticket);
  assert(!JSON.stringify(bindings.pm2ConfigurationObservation.value).includes('SECRET'));
  const count=calls.length;await execute('update');assert.equal(calls.length,count,'uncertain update was submitted twice');
  await execute('configuration');
  if(mode==='not-accepted'){
   assert(bindings.pm2ConfigurationObservation.value,'mere absence released an uncertain request');assert.equal(bindings.pm2ConfigurationAbsent.value,true);
   const before=calls.length;await execute('update');assert.equal(calls.length,before,'absence allowed a blind retry');
   Object.assign(bindings.form.value,{resource_id:ticket.appID,pm2_operation_id:ticket.operationID});await functions.cancelUnacceptedPM2Configuration();
   assert.equal(bindings.pm2ConfigurationObservation.value,undefined,'durable cancellation failed to release the original nonce');
   assert.equal(bindings.form.value.confirm,'');assert.equal(bindings.form.value.expected_revision,0);assert.equal(calls.at(-1).path,'/app-modules/pm2-manager/cancel-configuration-request');
  }else if(mode==='refresh-corrupt')assert(bindings.pm2ConfigurationObservation.value,'unresolved or foreign record released submission');
  else assert.equal(bindings.pm2ConfigurationObservation.value,undefined,'original terminal observation failed to release submission');
 }
});
test('actual project selection fills resource and revision independently of transaction recovery',()=>{
 const selected=source.slice(source.indexOf('function selected('),source.indexOf('function inputBody('));
 const code=ts.transpileModule(selected,{compilerOptions:{target:ts.ScriptTarget.ES2022}}).outputText;
 const bindings={definition:{value:{id:'pm2-manager',fields:[{key:'entry',kind:'text'},{key:'memory_mb',kind:'number'}]}},form:{value:{}},selectedPlanID:{value:''},activeTab:{value:'apps'},workspace:{value:[{id:'control'},{id:'configuration'}]},integrityModule:{value:false},clearWriteOnlyFields:()=>{},pm2ConfigurationFields,ElMessage:{info:()=>{},error:()=>{}}};
 const choose=new Function('bindings','with(bindings){'+code+';return selected;}')(bindings);
 choose({id:sample.resource_id,site_id:sample.site_id,revision:7,entry:'app.js',memory_mb:128});
 assert.equal(bindings.form.value.resource_id,sample.resource_id);assert.equal(bindings.form.value.expected_revision,7);assert.equal(bindings.selectedPlanID.value,sample.resource_id);
 choose({...sample,state:'needs_attention'});assert.equal(bindings.activeTab.value,'configuration');assert.equal(bindings.form.value.pm2_operation_id,sample.pm2_operation_id);assert.equal(bindings.form.value.confirm,'');
});

