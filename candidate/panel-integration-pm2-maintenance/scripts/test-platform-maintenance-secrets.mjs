// Execute the actual TypeScript setup with explicit synthetic inventory/clock.
// This is a compiled-source regression, not signed/installed/remote proof.
import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {createHash,webcrypto} from 'node:crypto';
import ts from '../web/node_modules/typescript/lib/typescript.js';
const source=readFileSync(new URL('../web/src/PlatformMaintenance.vue',import.meta.url),'utf8');
const setup=source.slice(source.indexOf('>')+1,source.indexOf('</script>'));
const js=ts.transpileModule(setup,{compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.CommonJS}}).outputText;
const hash=s=>createHash('sha256').update(s).digest('hex');
function fixture(){
 let now=1800000000000,serial=0,failure='',change=g=>g;
 const timers=new Map(),calls=[],watches=[],unmounts=[],owner='b'.repeat(32),instance='d'.repeat(32);
 let remote,token='a'.repeat(64);
 const props={installed:true,installationId:instance,access:{user_id:owner,role:'admin',menu_ids:[]},api:async(path,method='GET',body)=>{
  calls.push({path,method});if(failure&&path.endsWith(failure))throw Error('synthetic inventory unavailable');
  if(path.endsWith('/operations'))return{limit:1024,read_only:true,entries:[]};
  if(path.endsWith('/grants')&&method==='GET')return{limit:128,read_only:true,entries:change(remote?[{...remote}]:[])};
  if(path.endsWith('/grants')&&method==='POST'){
   remote={grant_id:hash(token),commands:body.commands,expires_at:Math.floor(now/1000)+300,revoked:false,owner_id:owner,installation_id:instance,legacy_unbound:false,revocable:true};
   return{token,...remote,scope:'nginx-maintenance',one_time_secret:true};
  }
  throw Error('unexpected synthetic request');
 }};
 const vue={ref:value=>({value}),computed:f=>({get value(){return f();}}),watch:(...args)=>watches.push(args),onMounted:()=>{},onUnmounted:f=>unmounts.push(f)};
 const exports={},bindings=name=>name==='vue'?vue:{menuPermissionIDs:[],validAccessPlan:()=>true};
 const FakeDate=class extends Date{static now(){return now;}};
 const view=new Function('require','exports','defineProps','setTimeout','clearTimeout','crypto','Date',js+'\nreturn {secret,grantConfirm,issue,refresh,clear};')(
  bindings,exports,()=>props,(fn,delay)=>{const id=++serial;timers.set(id,{fn,delay});return id;},id=>timers.delete(id),webcrypto,FakeDate);
 return{view,timers,calls,watches,unmounts,props,issue:async()=>{view.grantConfirm.value='GRANT NGINX MAINTENANCE';await view.issue();},change:f=>{change=f;},fail:path=>{failure=path;},tick:ms=>{now+=ms;},replaceToken:s=>{token=s;}};
}
test('compiled setup retains only the same live owned instance-bound grant after complete read-only inventory',async()=>{
 const f=fixture();await f.issue();assert.equal(f.view.secret.value,'a'.repeat(64));assert.equal(f.timers.size,1);
 await f.view.refresh();assert.equal(f.view.secret.value,'a'.repeat(64));assert.equal(f.timers.size,1);
 assert.equal(f.calls.filter(c=>c.method==='POST').length,1);
});
for(const [name,change]of Object.entries({
 revoked:g=>[{...g[0],revoked:true}],expired:g=>[{...g[0],expires_at:1}],missing:()=>[],
 unbound:g=>[{...g[0],installation_id:'',legacy_unbound:true}],
 foreign_instance:g=>[{...g[0],installation_id:'e'.repeat(32)}],
 foreign_owner:g=>[{...g[0],owner_id:'e'.repeat(32)}],
 wrong_id:g=>[{...g[0],grant_id:'e'.repeat(64)}],
 malformed:g=>[{...g[0],revoked:0}],duplicate:g=>[g[0],g[0]],
}))test('compiled refresh hides issued secret and cancels timer after '+name,async()=>{
 const f=fixture();await f.issue();f.change(change);await f.view.refresh();assert.equal(f.view.secret.value,'');assert.equal(f.timers.size,0);
 assert.equal(f.calls.filter(c=>c.method==='POST').length,1,'inventory must never regenerate or revoke a grant');
});
for(const path of ['/grants','/operations'])test('incomplete '+path+' read fails closed for displayed secret without mutation',async()=>{
 const f=fixture();await f.issue();f.fail(path);await f.view.refresh();assert.equal(f.view.secret.value,'');assert.equal(f.timers.size,0);assert.equal(f.calls.filter(c=>c.method==='POST').length,1);
});
test('issued secret is hidden at expiry with no refresh, mutation or new token',async()=>{
 const f=fixture();await f.issue();const timer=[...f.timers.values()][0];assert.equal(timer.delay,300000);const count=f.calls.length;f.tick(300000);timer.fn();assert.equal(f.view.secret.value,'');assert.equal(f.timers.size,0);assert.equal(f.calls.length,count);
});
test('clearing account/install scope or unmounting removes secret and timer',async()=>{
 for(const trigger of ['clear','account','installation','unmount']){
  const f=fixture();await f.issue();
  if(trigger==='clear')f.view.clear();else if(trigger==='unmount')f.unmounts[0]();else f.watches[trigger==='account'?0:1][1]();
  assert.equal(f.view.secret.value,'');assert.equal(f.timers.size,0);
 }
});
test('missing verified owner identity cannot retain a displayed secret on refresh',async()=>{
 const f=fixture();await f.issue();delete f.props.access.user_id;await f.view.refresh();assert.equal(f.view.secret.value,'');assert.equal(f.timers.size,0);assert.equal(f.calls.filter(c=>c.method==='POST').length,1);
});
test('an already queued old expiry callback cannot hide a newly issued distinct grant',async()=>{
 const f=fixture();await f.issue();const old=[...f.timers.values()][0];f.replaceToken('e'.repeat(64));await f.issue();assert.equal(f.timers.size,1);old.fn();assert.equal(f.view.secret.value,'e'.repeat(64));assert.equal(f.timers.size,1);f.view.clear();
});
