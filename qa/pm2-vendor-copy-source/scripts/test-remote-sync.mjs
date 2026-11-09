import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import ts from '../web/node_modules/typescript/lib/typescript.js';
const transpile=source=>ts.transpileModule(source,{compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.ESNext}}).outputText;
const moduleURL=source=>'data:text/javascript;base64,'+Buffer.from(transpile(source)).toString('base64');
const registryURL=moduleURL(readFileSync(new URL('../web/src/registryRequestIdentity.ts',import.meta.url),'utf8'));
const remoteSource=readFileSync(new URL('../web/src/remoteSync.ts',import.meta.url),'utf8').replace('"./registryRequestIdentity.ts"',JSON.stringify(registryURL));
const {newRemoteRequestID,validRemoteJob,remoteJobTerminal,remoteQueueReplyMatches,remoteConnectionRow,RemoteRequestIdentity}=await import(moduleURL(remoteSource));
const job={remote_request_id:'a'.repeat(32),remote_target_id:'host-one',site_id:'b'.repeat(32),revision:2,state:'queued',copied_count:0,skipped_count:0};
test('portable fixed remote task identity has exact 128-bit hexadecimal shape',()=>{const values=new Set();for(let i=0;i<32;i++){const id=newRemoteRequestID();assert.match(id,/^[0-9a-f]{32}$/);values.add(id);}assert.equal(values.size,32);});
test('unknown, active or interrupted remote tasks cannot silently start a new request',()=>{for(const state of ['queued','running','interrupted','invented'])assert.equal(remoteJobTerminal({...job,state}),false);for(const state of ['succeeded','conflicts','failed','recovered'])assert.equal(remoteJobTerminal({...job,state}),true);for(const altered of [null,[],{}, {...job,copied_count:-1},{...job,revision:0},{...job,remote_request_id:'UUID'}])assert.equal(validRemoteJob(altered),false);});
test('queue replies must bind to exact request, target, source and connection revision',()=>{const body={remote_request_id:job.remote_request_id,remote_target_id:job.remote_target_id,site_id:job.site_id,expected_revision:job.revision};assert.equal(remoteQueueReplyMatches(job,body),true);for(const key of Object.keys(body))assert.equal(remoteQueueReplyMatches(job,{...body,[key]:'changed'}),false);});
function managerFunction(source,name){
 const setup=source.slice(source.indexOf('<script setup lang="ts">')+24,source.indexOf('</script>'));
 const ast=ts.createSourceFile('manager.ts',setup,ts.ScriptTarget.ES2022,true,ts.ScriptKind.TS);
 const fn=ast.statements.find(node=>ts.isFunctionDeclaration(node)&&node.name?.text===name);assert(fn,'actual manager function missing: '+name);return fn.getText(ast);
}
test('UI persists identity before its remote fetch, distinguishes accepted from complete and clears write-only secrets',()=>{const source=readFileSync(new URL('../web/src/AppModuleManager.vue',import.meta.url),'utf8'),execute=managerFunction(source,'execute');const persist=execute.indexOf('remoteRequestIdentity.begin(submitted)'),submit=execute.indexOf('const result = await props.api(');assert(persist>=0&&submit>persist,'actual remote execution must persist identity before its submission, not before an unrelated helper read');assert.match(source,/保留原任务标识/);assert.match(source,/尚未宣称同步完成/);assert.match(source,/if\(definition\.value\?\.id==="files-sync"\)clearWriteOnlyFields\(\)/);assert.match(source,/"secret-text"\].includes\(field.kind\)/);assert.match(source,/连接策略修订号/);assert.match(source,/remoteRequestIdentity\.bind/);assert.match(source,/reviewRemoteTicket/);assert.doesNotMatch(source,/localStorage.*remote_private_key|sessionStorage.*remote_private_key/);});
function memory(){const values=new Map();return {getItem:key=>values.get(key)??null,setItem:(key,value)=>values.set(key,value),removeItem:key=>values.delete(key),values};}
const actor='1'.repeat(32),body={site_id:job.site_id,remote_target_id:job.remote_target_id,expected_revision:job.revision,excludes:['z','a']};
test('actual compiled remote queue persists before its one fetch and clears secrets; storage failure blocks the fetch',async()=>{
 const source=readFileSync(new URL('../web/src/AppModuleManager.vue',import.meta.url),'utf8');
 for(const blocked of [false,true]){
  const store=memory();if(blocked)store.setItem=()=>{throw Error('synthetic unavailable session storage');};const identity=new RemoteRequestIdentity(store,()=>job.remote_request_id);identity.bind(actor);const calls=[],messages=[];
  const bindings={definition:{value:{id:'files-sync',actions:['queue-remote','run'],fields:[{key:'remote_private_key',kind:'secret-text'}]}},installedUnknown:{value:false},busy:{value:false},canExecutePHP:()=>true,idsAccessGeneration:7,inputBody:()=>structuredClone(body),remoteRequestIdentity:identity,form:{value:{remote_private_key:'synthetic-write-only-secret'}},error:{value:''},report:{value:undefined},integrityModule:{value:false},remoteQueueReplyMatches,
   props:{api:async(...args)=>{assert.equal(blocked,false);assert.equal(identity.list().length,1,'persisted ticket must already exist at network boundary');const independent=new RemoteRequestIdentity(store);independent.bind(actor);assert.equal(independent.list()[0].key,job.remote_request_id);calls.push(args);assert.equal(args[2].remote_request_id,job.remote_request_id);return {job};}},
   setReport:value=>{bindings.report.value=value;},ElMessage:{info:text=>messages.push(text),success:()=>{throw Error('queued must not claim completed');}},
  };
  const execute=new Function(...Object.keys(bindings),transpile(managerFunction(source,'clearWriteOnlyFields')+'\n'+managerFunction(source,'execute'))+';return execute;')(...Object.values(bindings));await execute('queue-remote');
  assert.equal(bindings.busy.value,false);assert.equal(bindings.form.value.remote_private_key,'');assert.equal(calls.length,blocked?0:1);
  if(blocked){assert.equal(bindings.error.value,'不能保存待核对任务标识，未提交；请允许本站会话存储');assert.equal(messages.length,0);}else{assert.equal(bindings.error.value,'');assert.equal(bindings.form.value.remote_request_id,job.remote_request_id);assert(messages.some(s=>s.includes('尚未宣称同步完成')));assert.equal(identity.list().length,1);}
 }
});
test('public nested connection survives table selection without carrying hidden authentication fields',()=>{const remote_target={address:'127.0.0.1',port:22,username:'user',host_key:'ssh-ed25519 AAAA',root:'/target',backup_root:'/backup',password:'hidden',remote_private_key:'hidden'};const row=remoteConnectionRow({remote_target});assert.equal(row.remote_target.address,'127.0.0.1');assert.deepEqual(Object.keys(row.remote_target).sort(),['address','backup_root','host_key','port','root','username']);assert.deepEqual(remoteConnectionRow({remote_target:{...remote_target,port:0}}),{});const source=readFileSync(new URL('../web/src/AppModuleReport.vue',import.meta.url),'utf8');assert.match(source,/remoteConnectionRow\(v\)/);assert.match(source,/return \["remote_target_id","remote_target"/);});
test('refresh and lost reply reuse exact account-bound remote task; altered request remains blocked',()=>{const store=memory();let created=0;const make=()=>new RemoteRequestIdentity(store,()=>{created++;return 'a'.repeat(32)});let identity=make();identity.bind(actor);const first=identity.begin(body);assert.equal(created,1);identity=make();identity.bind(actor);assert.equal(identity.begin({...body,excludes:['a','z']}).key,first.key);assert.equal(created,1);assert.throws(()=>identity.begin({...body,site_id:'c'.repeat(32)}));assert.throws(()=>identity.begin({...body,remote_request_id:'d'.repeat(32)}));assert.equal(identity.list().length,1);assert.ok(![...store.values.values()][0].includes('excludes'));});
test('only matching terminal server identity explicitly releases pending remote request',()=>{const store=memory();const identity=new RemoteRequestIdentity(store,()=>job.remote_request_id);identity.bind(actor);identity.begin(body);for(const state of ['queued','running','interrupted'])assert.throws(()=>identity.release({...job,state}));assert.throws(()=>identity.release({...job,state:'succeeded',revision:1}));assert.equal(identity.list().length,1);identity.release({...job,state:'succeeded'});assert.equal(identity.list().length,0);});
test('account changes, corrupted records and unavailable session storage fail closed',()=>{const store=memory();let identity=new RemoteRequestIdentity(store,()=>job.remote_request_id);identity.bind(actor);identity.begin(body);identity=new RemoteRequestIdentity(store);identity.bind('2'.repeat(32));assert.equal(identity.list().length,0);store.setItem('panel-remote-sync-pending-v1','{bad');identity.bind(actor);assert.throws(()=>identity.begin(body));const broken=new RemoteRequestIdentity({getItem:()=>null,removeItem:()=>{},setItem:()=>{throw Error('blocked')}});broken.bind(actor);assert.throws(()=>broken.begin(body));assert.equal(broken.list().length,0);});
test('preview labels do not claim writes; new-task preparation clears the previous report',async()=>{
 const source=readFileSync(new URL('../web/src/AppModuleReport.vue',import.meta.url),'utf8');
 const script=source.slice(source.indexOf('<script setup lang="ts">')+24,source.indexOf('</script>'));
 const ast=ts.createSourceFile('report.ts',script,ts.ScriptTarget.ES2022,true,ts.ScriptKind.TS);
 const fn=ast.statements.find(node=>ts.isFunctionDeclaration(node) && node.name?.text==='reportLabel');assert(fn);
 const {label}=await import(moduleURL('export function label(key:string,preview:boolean){const props={id:"files-sync",report:{preview}};const names:Record<string,string>={copied:"已复制",copied_count:"复制数"};'+fn.getText(ast)+';return reportLabel(key);}'));
 assert.equal(label('copied',true),'拟复制（尚未写入）');assert.equal(label('copied_count',true),'拟复制数');assert.equal(label('copied',false),'已复制');
 assert.match(source,/\{\{ reportLabel\(key\) \}\}/);
 const manager=readFileSync(new URL('../web/src/AppModuleManager.vue',import.meta.url),'utf8');assert.match(manager,/remote_request_id="";report\.value=undefined;activeTab\.value="remote-transfer"/);
});
test('archive uses server-provided full-record digest and clears stale confirmation on selection',()=>{
 const source=readFileSync(new URL('../web/src/AppModuleManager.vue',import.meta.url),'utf8');
 assert.match(source,/expected_sha:row\.job_sha256\|\|"",confirm:""/);
 assert.match(source,/"archive-remote-job": "按摘要归档所选终态任务（保留证据）"/);
 const report=readFileSync(new URL('../web/src/AppModuleReport.vue',import.meta.url),'utf8');assert.match(report,/job_archived: "任务已归档"/);
});
