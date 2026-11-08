import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import {fileURLToPath,pathToFileURL} from 'node:url';
const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
const ts=await import(pathToFileURL(path.join(root,'web/node_modules/typescript/lib/typescript.js')).href);
const data=code=>'data:text/javascript;base64,'+Buffer.from(code).toString('base64');
const compile=name=>ts.transpileModule(fs.readFileSync(path.join(root,'web/src',name),'utf8'),{compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.ESNext}}).outputText;
const menu=data(compile('menuPermissions.ts'));
let source=compile('integrityKernel.ts').replaceAll("'./menuPermissions'",JSON.stringify(menu));
for(const dependency of ['@noble/hashes/sha2.js','@noble/hashes/utils.js'])source=source.replaceAll(JSON.stringify(dependency),JSON.stringify(pathToFileURL(path.join(root,'web/node_modules',dependency)).href)).replaceAll("'"+dependency+"'",JSON.stringify(pathToFileURL(path.join(root,'web/node_modules',dependency)).href));
const k=await import(data(source)),m=await import(menu);
const site='1'.repeat(32),actor='3'.repeat(32),time='2026-11-05T01:02:03Z';
const input={site_id:site,expected_revision:0,expected_app_version:'1.5.0',baseline_sha:'a'.repeat(64),source_operation:'',source_sha:'',confirm:'PROTECT SITE '+site};
const request={format:1,id:'2'.repeat(32),actor_id:actor,access_revision:1,app_sha:'b'.repeat(64),action:'enable',input,created_at:time};
assert.equal(k.kernelRequestSHA(request),'a145ba1a816c689231e3b288930a83498a79f114e2d3dec4e7d35c0bb201b6ce');
assert.equal(k.kernelOperationID(actor,'original-key'),'bc7926e49fcda298a324b77c289b9cd5');
assert.match(k.kernelNewSubmissionKey(),/^[a-f0-9]{32}$/);
const originalKey='9'.repeat(32);request.id=k.kernelOperationID(actor,originalKey);
const queued={request,request_sha256:k.kernelRequestSHA(request),state:'queued',revision:1,plan_sha:'',enable_operation:'',files:0,directories:0,completed:0,error:'',finished_at:''};
assert.equal(k.kernelOperationValid(queued),true);
const pending={id:request.id,key:originalKey,actor,action:'enable',input};
assert.equal(k.kernelPendingMatches(pending,queued),true);
assert.equal(k.kernelPendingValid(pending,'4'.repeat(32)),false);
const clone=x=>structuredClone(x);
let checks=6;
for(const [name,edit]of Object.entries({
 actor:v=>v.request.actor_id='4'.repeat(32),id:v=>v.request.id='5'.repeat(32),site:v=>v.request.input.site_id='6'.repeat(32),version:v=>v.request.input.expected_app_version='1.4.1',grant:v=>v.request.access_revision++,manifest:v=>v.request.app_sha='c'.repeat(64),revision:v=>v.revision++,unconfirmed_success:v=>v.state='succeeded',success_with_error:v=>{v.state='succeeded';v.error='unknown'},unknown_without_error:v=>v.state='needs-attention',foreign_digest:v=>v.request_sha256='d'.repeat(64),out_of_budget:v=>v.files=10001,
})){const v=clone(queued);edit(v);assert.equal(k.kernelPendingMatches(pending,v),false,name);checks++}
const reordered=clone(queued);reordered.request.input=Object.fromEntries(Object.entries(reordered.request.input).reverse());assert.equal(k.kernelPendingMatches(pending,reordered),true);checks++;
const ready={site_id:site,app_version:'1.5.0',app_sha:request.app_sha,revision:0,state:'ready',baseline_sha:input.baseline_sha,baseline_files:1,cap_linux_immutable:true,verified_at:time,error:'',operations:[],scope:'Owned inode protection only'};
assert.equal(k.kernelStatusValid(ready,site),true);assert.deepEqual(k.kernelActionInput(ready,'enable',site),input);checks+=2;
for(const edit of [v=>v.cap_linux_immutable=false,v=>v.app_version='1.4.1',v=>v.app_sha='',v=>v.baseline_sha='',v=>v.state='running',v=>v.site_id='7'.repeat(32),v=>v.revision=1]){const v=clone(ready);edit(v);assert.throws(()=>k.kernelActionInput(v,'enable',site));checks++}
const enabledOperation={...clone(queued),state:'succeeded',plan_sha:'c'.repeat(64),enable_operation:request.id,files:1,directories:1,completed:2,finished_at:time};
const enabled={...clone(ready),revision:1,state:'enabled',operations:[enabledOperation],latest:enabledOperation};
assert.equal(k.kernelStatusValid(enabled,site),true);
const release=k.kernelActionInput(enabled,'release',site);assert.equal(release.source_operation,request.id);assert.equal(release.source_sha,enabledOperation.request_sha256);checks+=3;
for(const [name,edit]of Object.entries({missing_latest:v=>delete v.latest,borrowed_site:v=>v.operations[0].request.input.site_id='8'.repeat(32),invented_revision:v=>v.revision=2,unknown_marked_green:v=>{v.operations[0].state='needs-attention';v.operations[0].error='unknown'},incomplete_journal:v=>v.operations[0].completed=0,wrong_latest:v=>v.latest.request_sha256='f'.repeat(64)})){const v=clone(enabled);edit(v);assert.equal(k.kernelStatusValid(v,site),false,name);checks++}
const unknown=clone(enabled);unknown.state='needs-attention';unknown.operations[0].state='needs-attention';unknown.operations[0].error='Original intent without final outcome';unknown.latest=unknown.operations[0];
assert.equal(k.kernelStatusValid(unknown,site),true);assert.equal(k.kernelActionInput(unknown,'release',site).source_operation,request.id);assert.throws(()=>k.kernelActionInput(unknown,'enable',site));checks+=3;
assert.equal(k.kernelFullAdministrator({role:'admin',menu_ids:[...m.menuPermissionIDs]}),true);
assert.equal(k.kernelFullAdministrator({role:'admin',menu_ids:['security']}),false);
assert.equal(k.kernelFullAdministrator({role:'viewer',menu_ids:[...m.menuPermissionIDs]}),false);checks+=3;
assert.equal(k.kernelPendingValid(pending,actor),true);checks++;
const closure={format:1,id:'f'.repeat(32),request:clone(request),original_request_sha256:'',sealed_at:time};
const absent={id:pending.id,state:'absent'};
const sealed={id:pending.id,state:'sealed',closure};
assert.equal(k.kernelAdmissionMatches(pending,absent),true);assert.equal(k.kernelAdmissionMatches(pending,sealed),true);checks+=2;
for(const [name,edit]of Object.entries({actor:v=>v.closure.request.actor_id='8'.repeat(32),id:v=>v.id='8'.repeat(32),site:v=>v.closure.request.input.site_id='8'.repeat(32),action:v=>v.closure.request.action='release',original_without_record:v=>v.closure.original_request_sha256='b'.repeat(64),invalid_close_id:v=>v.closure.id='../escape',not_sealed:v=>v.state='succeeded'})){const v=clone(sealed);edit(v);assert.equal(k.kernelAdmissionMatches(pending,v),false,name);checks++}
const cancelled={...clone(queued),state:'cancelled',error:'Original queued request sealed before dispatch',finished_at:time};
const knownSealed={...clone(sealed),operation:cancelled};knownSealed.closure.original_request_sha256=cancelled.request_sha256;
assert.equal(k.kernelAdmissionMatches(pending,knownSealed),true);checks++;
const disguised=clone(knownSealed);disguised.operation=enabledOperation;
assert.equal(k.kernelAdmissionMatches(pending,disguised),false);checks++;
const knownOriginal={id:pending.id,state:'original',operation:enabledOperation};
assert.equal(k.kernelAdmissionMatches(pending,knownOriginal),true);checks++;
console.log(JSON.stringify({ok:true,checks,scope:'frontend identities, unknown outcomes, authority and action boundaries; not native installation or browser acceptance'}));
