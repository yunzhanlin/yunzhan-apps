import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import ts from '../web/node_modules/typescript/lib/typescript.js';
import {isUserMutation,userMutationReplyMatches,userMutationNeedsRead,userManagementListKnown} from '../web/src/userManagementReceipt.ts';
const snapshot={menu_catalog:[{id:'files',label:'文件',admin_only:false},{id:'panel-access',label:'账户授权',admin_only:true}],users:[{id:'a'.repeat(32),username:'test-reader',role:'viewer',site_ids:[],menu_ids:['files'],revision:3,full_admin:false,totp_enabled:false,sessions:2}]};
test('success acknowledgement binds only the exact current public user/action tuple',()=>{
 for(const action of ['create','update','revoke','delete']) {
  assert(isUserMutation(action));const good={username:'test-reader',action,ok:true};assert(userMutationReplyMatches(action,'test-reader',good));
  for(const bad of [null,[],{}, {...good,username:'foreign-user'},{...good,action:'run'},{...good,ok:1},{...good,ok:false},{...good,password:'secret'},{...good,token:'secret'},Object.create(good)])assert(!userMutationReplyMatches(action,'test-reader',bad));
 }
 for(const action of ['run','install','anything'])assert(!isUserMutation(action));
 assert(!userMutationReplyMatches('update','',{}));
});
test('unknown outcomes block only writes until a real readonly list is validated',()=>{
 for(const state of ['unverified','refresh_failed']) {
  const record={action:'update',username:'test-reader',state};
  for(const action of ['create','update','revoke','delete'])assert(userMutationNeedsRead(record,action));
  assert(!userMutationNeedsRead(record,'run'));
 }
 assert(!userMutationNeedsRead({action:'update',username:'test-reader',state:'acknowledged'},'update'));
 assert(userManagementListKnown(snapshot));assert(userManagementListKnown({...snapshot,users:[]}));
 for(const bad of [null,[],{}, {...snapshot,users:[null]}, {...snapshot,menu_catalog:[]}, {...snapshot,menu_catalog:[...snapshot.menu_catalog,snapshot.menu_catalog[0]]}])assert(!userManagementListKnown(bad));
 for(const patch of [{id:'foreign'}, {username:'!'}, {role:{toString:'viewer'}}, {role:'root'}, {revision:0}, {revision:'3'}, {sessions:null}, {sessions:-1}, {full_admin:true}, {totp_enabled:0}, {menu_ids:['foreign']}, {menu_ids:['files','files']}, {menu_ids:['panel-access']}, {site_ids:['foreign']}])assert(!userManagementListKnown({...snapshot,users:[{...snapshot.users[0],...patch}]}));
 assert(!userManagementListKnown({...snapshot,users:[snapshot.users[0],snapshot.users[0]]}));
});
const source=readFileSync(new URL('../web/src/AppModuleManager.vue',import.meta.url),'utf8');
const actual=source.slice(source.indexOf('async function execute('),source.indexOf('async function reviewRemoteTicket('));
const js=ts.transpileModule(actual,{compilerOptions:{target:ts.ScriptTarget.ES2022}}).outputText;
test('actual component preserves acknowledgements, forbids blind retries, clears password and focuses the error',async()=>{
 for(const mode of ['success','refused','lost-reply','foreign-reply','refresh-failed','refresh-corrupt','revoked']) {
  const calls=[],notices=[],anchor=[];const body={username:'test-reader',password:'OWNED-UNIT-ONLY-SECRET',role:'viewer',menu_ids:['files'],expected_revision:3};
  const bindings={definition:{value:{id:'user-manager',actions:['run','update'],fields:[{key:'password',kind:'password'}]}},installedUnknown:{value:false},busy:{value:false},visible:{value:true},error:{value:''},form:{value:{...body}},report:{value:structuredClone(snapshot)},selectedPlanID:{value:'test-reader'},userMutationObservation:{value:undefined},userErrorAnchor:{value:{scrollIntoView:v=>anchor.push(['scroll',v]),focus:v=>anchor.push(['focus',v])}},idsAccessGeneration:1,integrityModule:{value:false},canExecutePHP:()=>true,isUserMutation,userMutationReplyMatches,userMutationNeedsRead,userManagementListKnown,inputBody:()=>({...body}),nextTick:async()=>{},ElMessage:{info:()=>{},success:message=>notices.push(message)},setReport:value=>{bindings.report.value=value;},clearWriteOnlyFields:()=>{bindings.form.value.password='';},menuCatalog:{value:snapshot.menu_catalog},roleDefaultMenus:()=>assert.fail('explicit current menu grants must not be reset'),props:{api:async(path,method,incoming)=>{
   calls.push({path,method});
   if(path.endsWith('/update')) {
    assert.deepEqual(incoming,body);
    if(mode==='refused'||mode==='lost-reply')throw Error(mode==='refused'?'账户改动与审计未共同提交':'response unavailable');
    if(mode==='revoked')bindings.idsAccessGeneration++;
    return {username:mode==='foreign-reply'?'foreign-user':body.username,action:'update',ok:true};
   }
   assert(path.endsWith('/run')&&method==='POST');
   if(mode==='refresh-failed'&&calls.length===2)throw Error('readonly list failed');
   return mode==='refresh-corrupt'?{users:[{username:'test-reader'}],menu_catalog:snapshot.menu_catalog}:{...structuredClone(snapshot),users:[{...snapshot.users[0],revision:4,sessions:0}]};
  }}};
  const execute=new Function('bindings','with(bindings){'+js+';return execute;}')(bindings);await execute('update');
  assert.equal(bindings.busy.value,false);
  if(mode==='revoked') {assert.equal(calls.length,1);assert.equal(notices.length,0);assert.equal(bindings.userMutationObservation.value,undefined);continue;}
  assert.equal(bindings.form.value.password,'');
  if(mode==='success') {assert.equal(calls.length,2);assert.equal(notices.length,1);assert.equal(bindings.form.value.expected_revision,4);assert.equal(bindings.userMutationObservation.value.state,'acknowledged');assert.equal(anchor.length,0);continue;}
  const committed=mode.startsWith('refresh-');assert.equal(bindings.userMutationObservation.value.state,committed?'refresh_failed':'unverified');assert.equal(notices.length,committed?1:0);assert.equal(calls.length,committed?2:1);assert.equal(bindings.form.value.expected_revision,0);assert.equal(bindings.selectedPlanID.value,'');assert.equal(anchor.length,2);assert(!JSON.stringify(bindings.userMutationObservation.value).includes('SECRET'));
  if(committed)assert.match(bindings.error.value,/已收到服务器账户操作成功回执/);
  const count=calls.length;await execute('update');assert.equal(calls.length,count,'blocked mutation auto-retried');
  if(mode==='refresh-corrupt') {await execute('run');assert.equal(bindings.userMutationObservation.value.state,'refresh_failed','malformed readonly list unblocked writes');}
  else {await execute('run');assert.equal(bindings.userMutationObservation.value,undefined,'valid explicit readonly list failed to unblock writes');}
 }
});
test('signed component exposes error anchor, pending-write guard and explicit readonly list action',()=>{
 assert.match(source,/ref="userErrorAnchor" tabindex="-1"/);assert.match(source,/userMutationNeedsRead\(userMutationObservation, action\)/);assert.match(source,/只读刷新账户列表/);assert.match(source,/已暂停重复写入/);
});
