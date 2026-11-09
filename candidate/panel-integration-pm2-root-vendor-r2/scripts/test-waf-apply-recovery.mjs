import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import ts from '../web/node_modules/typescript/lib/typescript.js';
import {decodeWafOriginalSummary,decodeWafOriginalPage,decodeWafOriginalRequest,readWafOriginalPage,readWafOriginalRequest,wafRecoveredApplyTicket} from '../web/src/wafApplyRecovery.ts';
const app='nginx-waf',id='1'.repeat(32);
const summary=()=>({id,target_id:app,kind:'software_configure',state:'queued',created_at:'2026-10-11T00:00:00Z',request_sha256:'a'.repeat(64),signed_install_binding:false});
const settings=()=>({profile:'balanced',rate_per_second:20,policy:{schema_version:2,revision:7,mode:'off',cc_enabled:false,burst:60,groups:{},lists:{},rules:[],sites:[],cc_rules:[]}});
const page=()=>({entries:[summary()],next_cursor:'',read_only:true});
const original=()=>({request:summary(),error:'',settings:settings(),read_only:true});
test('own request directory is closed, ordered and bounded to one 20-row page',()=>{
 assert.deepEqual(decodeWafOriginalPage(app,page()),page());
 for(const value of [null,[],{}, {...page(),actor_id:'private'},{...page(),read_only:false},{...page(),entries:null},{...page(),entries:[summary(),summary()]},{...page(),next_cursor:id},{...page(),entries:Array(21).fill(summary())}])assert.throws(()=>decodeWafOriginalPage(app,value));
 for(const change of [{target_id:'apache-waf'},{kind:'software_update'},{state:'healthy'},{created_at:'2026-02-30T00:00:00Z'},{request_sha256:'A'.repeat(64)},{signed_install_binding:true},{id:'BAD'},{private_path:'/private'}])assert.throws(()=>decodeWafOriginalSummary(app,{...summary(),...change}));
});
test('only immutable selected identity is adopted; an ordinary state transition is allowed',()=>{
 const value=original();value.request.state='succeeded';assert.deepEqual(decodeWafOriginalRequest(app,value,summary()),value);
 for(const change of [{id:'2'.repeat(32)},{kind:'software_install'},{request_sha256:'b'.repeat(64)},{created_at:'2026-10-11T00:00:01Z'}])assert.throws(()=>decodeWafOriginalRequest(app,{...original(),request:{...summary(),...change}},summary()));
 for(const value of [{...original(),actor_id:'private'},{...original(),read_only:false},{...original(),error:'汉'.repeat(10923)},{...original(),settings:{...settings(),password:'private'}},{...original(),settings:{...settings(),policy:{...settings().policy,revision:Number.MAX_SAFE_INTEGER}}},{...original(),settings:{...settings(),body:{text:'x'.repeat(130*1024)}}}])assert.throws(()=>decodeWafOriginalRequest(app,value,summary()));
});
test('read helpers use only fixed GET identities and never auto-submit an archive or configuration',async()=>{
 const paths=[];const read=async(...args)=>{assert.equal(args.length,1);paths.push(args[0]);return args[0].endsWith('/requests')?page():original();};
 await readWafOriginalPage(read,()=>true,app);await readWafOriginalRequest(read,()=>true,app,summary());assert.deepEqual(paths,[`/software/${app}/requests`,`/software/${app}/requests/${id}`]);
 await assert.rejects(readWafOriginalPage(read,()=>true,app,'/private'));assert.equal(paths.length,2);
});
test('closed/current-account guards discard late replies before publishing or chaining reads',async()=>{
 for(const fn of [()=>readWafOriginalPage(async()=>assert.fail('closed directory'),()=>false,app),()=>readWafOriginalRequest(async()=>assert.fail('closed detail'),()=>false,app,summary())])await assert.rejects(fn());
 let live=true;await assert.rejects(readWafOriginalPage(async()=>{live=false;return page();},()=>live,app));
 live=true;await assert.rejects(readWafOriginalRequest(async()=>{live=false;return original();},()=>live,app,summary()));
});
test('restored ticket is immutable, known-job-only and cannot inherit an edited draft',()=>{
 const value=original(),ticket=wafRecoveredApplyTicket(app,value);assert.ok(Object.isFrozen(ticket));assert.ok(Object.isFrozen(ticket.settings.policy));assert.equal(ticket.job,id);assert.equal(ticket.key,'');assert.equal(ticket.kind,'software_configure');
 value.settings.policy.mode='block';assert.equal(ticket.settings.policy.mode,'off');assert.throws(()=>{ticket.settings.policy.mode='observe';});
});

function component(){
 const source=readFileSync(new URL('../web/src/WafApplyRecovery.vue',import.meta.url),'utf8');
 const code=source.slice(source.indexOf('async function load('),source.indexOf('watch(()=>props.active'));
 const js=ts.transpileModule(code,{compilerOptions:{target:ts.ScriptTarget.ES2022}}).outputText;
 const events=[],b={props:{engine:app,active:true,blocked:false,api:async path=>path.endsWith('/requests')?page():original()},page:{value:page()},error:{value:''},busy:{value:false},generation:0,disposed:false,readWafOriginalPage,readWafOriginalRequest,emit:(name,value)=>events.push([name,value])};
 return {b,events,...new Function('b','with(b){'+js+';return {load,restore,invalidate};}')(b)};
}
test('actual recovery component only reads a selected original and emits adoption without applying it',async()=>{
 const {b,events,load,restore}=component();const paths=[];
 b.props.api=async(...args)=>{assert.equal(args.length,1);paths.push(args[0]);return args[0].endsWith('/requests')?page():original();};
 await load();assert.equal(events.length,0);await restore(summary());assert.deepEqual(paths,[`/software/${app}/requests`,`/software/${app}/requests/${id}`]);assert.equal(events.length,1);assert.equal(events[0][0],'restore');assert.deepEqual(events[0][1],original());
});
test('actual component refuses replacement before or during a read and clears stale directory on failure',async()=>{
 const {b,events,load,restore}=component();b.props.blocked=true;b.props.api=async()=>assert.fail('blocked restore read');await restore(summary());assert.equal(events.length,0);
 b.props.blocked=false;b.props.api=async()=>{b.props.blocked=true;return original();};await restore(summary());assert.equal(events.length,0);assert.equal(b.busy.value,false);
 b.props.api=async()=>{assert.equal(b.page.value,undefined);throw new Error('directory unavailable');};await load();assert.equal(b.page.value,undefined);assert.equal(b.error.value,'directory unavailable');assert.equal(events.length,0);
});
test('actual close/new context never adopts a late detail or publishes a late directory',async()=>{
 for(const operation of ['directory','detail']){
  const {b,events,load,restore,invalidate}=component();let resolve;b.props.api=()=>new Promise(r=>{resolve=r;});const old=operation==='directory'?load():restore(summary());
  b.props.active=false;invalidate();b.props.active=true;b.props.api=async()=>({...page(),entries:[]});await load();resolve(operation==='directory'?page():original());await old;assert.equal(events.length,0);assert.equal(b.page.value.entries.length,0);assert.equal(b.busy.value,false);assert.equal(b.error.value,'');
 }
});
test('actual parent adopts a known immutable job only; pending/closed parents refuse replacement',()=>{
 const source=readFileSync(new URL('../web/src/WafWorkspace.vue',import.meta.url),'utf8');
 const code=source.slice(source.indexOf('function recoverOriginalApply('),source.indexOf('async function apply()'));
 const js=ts.transpileModule(code,{compilerOptions:{target:ts.ScriptTarget.ES2022}}).outputText;
 const b={disposed:false,busy:{value:false},pendingApply:{value:undefined},recoveredApplyNote:{value:''},error:{value:''},saved:{value:'old success'},engine:app,wafRecoveredApplyTicket};
 const adopt=new Function('b','with(b){'+js+';return recoverOriginalApply;}')(b);adopt(original());assert.equal(b.pendingApply.value.job,id);assert.equal(b.pendingApply.value.key,'');assert.equal(b.saved.value,'');assert.match(b.recoveredApplyNote.value,/尚未核对实际结果/);
 const first=b.pendingApply.value;adopt({...original(),request:{...summary(),id:'2'.repeat(32)}});assert.equal(b.pendingApply.value,first);
 b.pendingApply.value=undefined;b.disposed=true;adopt(original());assert.equal(b.pendingApply.value,undefined);
 assert.match(source,/<WafApplyRecovery :api="api" :engine="engine" :active="tab==='request-recovery'" :blocked="!!pendingApply \|\| busy" @restore="recoverOriginalApply"/);
});
test('actual responsive UI keeps both original identities and the guarded restore operation accessible',()=>{
 const source=readFileSync(new URL('../web/src/WafApplyRecovery.vue',import.meta.url),'utf8');
 assert.match(source,/<el-table-column label="操作" width="155" fixed="right"/);
 const cards=source.slice(source.indexOf('<div class="original-cards">'),source.indexOf('<div class="recovery-actions">'));
 assert.match(cards,/v-for="row in page.entries" :key="row.id"/);assert.match(cards,/row.id/);assert.match(cards,/row.request_sha256/);assert.match(cards,/row.created_at/);assert.match(cards,/stateLabel\(row.state\)/);assert.match(cards,/row.signed_install_binding/);
 assert.match(cards,/:disabled="busy \|\| blocked \|\| !active" @click="restore\(row\)"/);assert.match(cards,/不能据此认定没有提交/);
 assert.match(source,/@media\(max-width:600px\)[\s\S]*?\.original-table\{display:none\}\.original-cards\{display:block\}/);
 // Template structure only; real DOM/render/click/keyboard proof belongs to
 // the browser suite rather than this source-backed host assertion.
});
