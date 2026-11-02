import {test} from "node:test";
import assert from "node:assert/strict";
import {readFileSync} from "node:fs";
import {createRequire} from "node:module";
import {beforeLoadBalanceStreamBuild} from "./release-build-baseline.mjs";
import ts from "../web/node_modules/typescript/lib/typescript.js";
const read=p=>readFileSync(new URL("../"+p,import.meta.url),"utf8");
const compiled=ts.transpileModule(read("web/src/apacheNumericLogs.ts"),{compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.ESNext}}).outputText;
const guards=await import("data:text/javascript;base64,"+Buffer.from(compiled).toString("base64"));
const {apacheLogArchive,apacheLogInventory,apacheLogExport,apacheLogActionReceipt}=guards;
const id="a".repeat(32),sha="b".repeat(64);
const row={id,captured_at:"2026-11-01T20:00:00Z",bytes:500,sha256:sha,state:"completed"};
const fixture=(rows=[row])=>({archives:structuredClone(rows),recovery:[],index_stages:[],inventory_complete:true,maintenance_healthy:true,max_archives:8,max_archive_bytes:33554432,read_only:true,numeric_only:true,rotation_reloads_apache:false});
const event={time:"2026-11-01T20:00:00Z",engine_version:"2.9.15-yz5",site_id:"c".repeat(32),rule_id:941100,phase:2,severity:2,mode:"block",intercepted_mark:true};
const exported=()=>({archive:structuredClone(row),metadata:{events:[event],available:true,partial:false,rejected_lines:0,log_bytes:500,max_bytes:33554432,capacity_near_limit:false,metadata_best_effort:true},export_contract:"numeric_only_recent_4MiB_5000_rules_not_full_raw_archive",selected_snapshot_digest_verified:true,inventory_not_claimed_complete:true});
test("complete bounded inventory, cross-record integrity and numeric export privacy",()=>{
 assert.equal(apacheLogInventory(fixture()),true);assert.equal(apacheLogExport(exported(),row),true);
 for(const update of [{inventory_complete:false},{maintenance_healthy:false},{rotation_reloads_apache:true},{archives:[row,row]},{max_archive_bytes:1000000000},{private_body:"secret"}])assert.equal(apacheLogInventory({...fixture(),...update}),false);
 for(const update of [{state:"future"},{id:"../etc/shadow"},{bytes:-1},{state:"completed",bytes:0},{sha256:"B".repeat(64)}])assert.equal(apacheLogArchive({...row,...update}),false);
 for(const update of [{private_body:"secret"},{archive:{...row,sha256:"c".repeat(64)}},{selected_snapshot_digest_verified:false}])assert.equal(apacheLogExport({...exported(),...update},row),false);
 assert.equal(apacheLogExport({...exported(),metadata:{...exported().metadata,events:[{...event,cookie:"secret"}]}},row),false);
 assert.equal(apacheLogActionReceipt({archive:row,same_inode_rotation:true,no_nginx_reload:true},"rotate"),false);
 const pending={...row,state:"prepared"};const inventory={...fixture([pending]),maintenance_healthy:false,recovery:[{archive:pending,index_sha256:sha,snapshot_sha256:sha,snapshot_bytes:500,snapshot_missing:false}]};
 assert.equal(apacheLogInventory(inventory),true);
 assert.equal(apacheLogInventory({...inventory,recovery:[{...inventory.recovery[0],archive:{...pending,bytes:501}}]}),false);
});
const vue=createRequire(new URL("../web/package.json",import.meta.url))("vue");
const source=read("web/src/ApacheNumericLogs.vue");
const start=source.indexOf("const inventory=ref"),end=source.indexOf("watch(()=>[props.active");
assert(start>=0&&end>start);
const actual=ts.transpileModule(source.slice(start,end),{compilerOptions:{target:ts.ScriptTarget.ES2022}}).outputText;
function component(mode="success",version="2.4.0",confirmOverride){
 const calls=[];let current=fixture();
 const props=vue.reactive({active:true,installed:true,version,parentBusy:false,api:async(path,method,body)=>{
  calls.push({path,method,body:structuredClone(body)});
  if(method==="POST"){
   assert.equal(path,"/software/apache-waf/body-log/rotate");assert.deepEqual(body,{});
   const next={...row,id:"d".repeat(32)};current=fixture([row,next]);
   if(mode==="lost-reply")throw Error("original result unknown");
   return {archive:mode==="foreign-reply"?{...next,state:"prepared"}:next,same_inode_rotation:true,no_apache_reload:true};
  }
  assert.equal(path,"/software/apache-waf/body-log/archives");
  return mode==="bad-inventory"?{...current,inventory_complete:false}:structuredClone(current);
 }});
 const bindings={...guards,props,computed:vue.computed,ref:vue.ref,ElMessageBox:{confirm:confirmOverride??(async()=>{}),prompt:async(text,title,opts)=>({value:opts.inputPlaceholder})},document:{createElement:()=>({click(){throw Error("test did not authorize download")}})}};
 const logic=new Function("bindings","with(bindings){"+actual+";return{inventory,known,unknown,error,receipt,reading,writing,confirming,supported,blocked,automaticBlocked,refresh,action,exportSnapshot};}")(bindings);
 // This isolated parent fixture represents the child's validated status event.
 // Its unknown/error behavior is exercised independently below.
 logic.automaticBlocked.value=false;
 return {calls,props,logic};
}
test("actual component only admits exact native version, known inventory and idle parent",async()=>{
 for(const version of ["2.3.0","2.4.1","2.4.0-beta","v2.4.0",""]){
  const t=component("success",version);await t.logic.refresh();await t.logic.action("rotate");assert.equal(t.calls.length,0,version);
 }
 const t=component();await t.logic.action("rotate");assert.equal(t.calls.length,0);
 await t.logic.refresh();t.props.parentBusy=true;await t.logic.action("rotate");assert.equal(t.calls.length,1);
 t.props.parentBusy=false;await t.logic.action("rotate");assert.equal(t.calls.filter(x=>x.method==="POST").length,1);assert.equal(t.calls.length,3);assert.equal(t.logic.known.value,true);assert.match(t.logic.receipt.value,/未重载 Apache/);
});
test("actual component retains lost/invalid receipts and requires an explicit read before another write",async()=>{
 for(const mode of ["lost-reply","foreign-reply"]){
  const t=component(mode);await t.logic.refresh();await t.logic.action("rotate");
  assert.equal(t.calls.length,2);assert.equal(t.logic.unknown.value,true);assert.equal(t.logic.known.value,false);assert.equal(t.logic.receipt.value,"");assert.match(t.logic.error.value,/不会自动重试/);
  await t.logic.action("rotate");assert.equal(t.calls.length,2);
  await t.logic.refresh();assert.equal(t.calls.length,3);assert.equal(t.logic.unknown.value,false);assert.equal(t.logic.known.value,true);assert.equal(t.calls.filter(x=>x.method==="POST").length,1);
 }
});
test("actual double click opens one confirmation and sends at most one rotation",async()=>{
 let accept;const prompt=new Promise(resolve=>{accept=resolve});let confirms=0;
 const t=component("success","2.4.0",()=>{confirms++;return prompt});await t.logic.refresh();
 const first=t.logic.action("rotate");await Promise.resolve();await t.logic.action("rotate");assert.equal(confirms,1);assert.equal(t.logic.confirming.value,true);
 accept();await first;assert.equal(t.calls.filter(x=>x.method==="POST").length,1);
});
test("failed or late inventory is never displayed as verified zero",async()=>{
 const t=component("bad-inventory");await t.logic.refresh();assert.equal(t.logic.known.value,false);assert.equal(t.logic.inventory.value,undefined);assert.match(t.logic.error.value,/未显示为空/);await t.logic.action("rotate");assert.equal(t.calls.length,1);
 let reply;const late=component();late.props.api=async()=>new Promise(resolve=>{reply=resolve});const read=late.logic.refresh();late.props.active=false;reply(fixture());await read;assert.equal(late.logic.inventory.value,undefined);assert.equal(late.logic.known.value,false);
});
test("real workspace exposes a separate maintenance pane and keeps automatic deletion absent",()=>{
 const workspace=read("web/src/WafWorkspace.vue");assert(workspace.includes('name="apache-numeric-logs"'));assert(workspace.includes('<ApacheNumericLogs :api="api"'));
 assert(source.includes("<ApacheLogAutomation"));assert(source.includes("自动轮转须明确保存策略"));assert(!source.includes("setInterval"));assert(!source.includes("onMounted("));
});


test("normal packaging always executes the new maintenance UI contracts",()=>{const builder=read("packaging/build-release.sh");assert(builder.includes("scripts/test-apache-numeric-logs.mjs"));assert(builder.includes("go test ./... -timeout=30m && go vet ./..."));});
test("historical build digests reverse only the exact new gate and explicit suite budget",()=>{
 const builder=read("packaging/build-release.sh");
 const gate='(cd "$BUILD_ROOT" && /opt/homebrew/bin/node --test scripts/test-apache-numeric-logs.mjs) 2>&1 | tee -a "$STAGE/$NAME/BUILD_CHECKS.txt"\n';
 const budget='go test ./... -timeout=30m && go vet ./...';
 const baseline=beforeLoadBalanceStreamBuild(builder);
 for(const changed of [builder.replace(gate,""),builder.replace(gate,gate+gate),builder.replace(gate,gate.replace("--test","--check")),builder.replace(budget,"go test ./... && go vet ./..."),builder.replace(budget,budget+budget),builder.replace(budget,budget.replace("30m","1m"))])assert.throws(()=>beforeLoadBalanceStreamBuild(changed));
 assert.notEqual(beforeLoadBalanceStreamBuild(builder.replace("go vet ./...","go vet ./... -unknown-flag")),baseline);
});

const automationModule=ts.transpileModule(read('web/src/apacheLogAutomation.ts'),{compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.ESNext}}).outputText.replace('"./apacheNumericLogs"',JSON.stringify('data:text/javascript;base64,'+Buffer.from(compiled).toString('base64')));
const autoGuards=await import('data:text/javascript;base64,'+Buffer.from(automationModule).toString('base64'));
const automaticFixture=()=>({configured:true,policy_revision:1,policy:{enabled:false,rotate_mib:16,max_age_minutes:60},record:{format:1,config_revision:1,policy:{enabled:false,rotate_mib:16,max_age_minutes:60},id:'e'.repeat(32),state:'idle',window_started_at:'2026-11-02T00:00:00Z',checked_at:'2026-11-02T00:00:00Z',policy_revision:0,log_bytes:0,archive_count:0,history:[]},record_sha256:'f'.repeat(64),read_only:true,core_maintenance:true,check_interval_seconds:60,automatic_deletion:false});
const autoSource=read('web/src/ApacheLogAutomation.vue');
const autoActual=ts.transpileModule(autoSource.slice(autoSource.indexOf('const applied=ref'),autoSource.indexOf('watch(()=>[props.active')),{compilerOptions:{target:ts.ScriptTarget.ES2022}}).outputText;
function automaticComponent(mode='success',version='2.4.0'){
 const calls=[],events=[];let server=automaticFixture();
 const props=vue.reactive({active:true,installed:true,version,parentBusy:false,api:async(path,method,body)=>{
  calls.push({path,method,body:structuredClone(body)});
  if(method==='POST'){
   assert.equal(path,'/software/apache-waf/body-log/automatic/configure');
   assert.equal(body.expected_revision,server.policy_revision);
   const next={enabled:body.enabled,rotate_mib:body.rotate_mib,max_age_minutes:body.max_age_minutes};
   server.policy=next;server.policy_revision++;server.record.policy=structuredClone(next);server.record.config_revision=server.policy_revision;
   if(mode==='lost-reply')throw Error('original result unavailable');
   const reply=structuredClone(server);if(mode==='foreign-reply')reply.policy_revision++;
   return reply;
  }
  assert.equal(path,'/software/apache-waf/body-log/automatic');
  return mode==='bad-status'?{...structuredClone(server),record_sha256:''}:structuredClone(server);
 }});
 const bindings={...autoGuards,props,computed:vue.computed,ref:vue.ref,emit:(...event)=>events.push(event),ElMessageBox:{prompt:async(text,title,opts)=>({value:opts.inputPlaceholder})}};
 const logic=new Function('bindings','with(bindings){'+autoActual+';return{applied,draft,draftRevision,known,uncertain,error,receipt,reading,writing,dirty,staleDraft,validDraft,availabilityChanged,readStatus,save,retain,resetDraft};}')(bindings);
 return{props,calls,events,logic,server};
}
test('automatic log status rejects contradictory identity, unsafe privacy fields and capacity',()=>{
 const good=automaticFixture();assert.equal(autoGuards.apacheAutomationStatus(good),true);
 assert.equal(autoGuards.apacheAutomationStatus({configured:false,policy_revision:0,policy:autoGuards.apacheAutomationDefaults(),record:null,record_sha256:'',read_only:true,core_maintenance:true,check_interval_seconds:60,automatic_deletion:false}),true);
 for(const change of [{policy_revision:0},{configured:false},{automatic_deletion:true},{check_interval_seconds:1},{raw_log:'private'},{record:{...good.record,config_revision:2}},{record:{...good.record,archive_count:9}},{record:{...good.record,state:'completed'}},{policy:{...good.policy,rotate_mib:29}},{record:{...good.record,history:Array(17).fill({id,at:good.record.checked_at,outcome:'unknown_retained'})}}])assert.equal(autoGuards.apacheAutomationStatus({...good,...change}),false);
});
test('actual automatic component preserves drafts and rejects a competing configuration revision',async()=>{
 const t=automaticComponent();await t.logic.readStatus(true);assert.equal(t.calls.length,1);
 t.logic.draft.value.rotate_mib=4;t.server.record.checked_at='2026-11-02T00:01:00Z';await t.logic.readStatus();
 assert.equal(t.logic.draft.value.rotate_mib,4);assert.equal(t.logic.applied.value.policy.rotate_mib,16);assert.equal(t.logic.draftRevision.value,1);
 t.server.policy_revision=2;t.server.record.config_revision=2;t.server.policy.rotate_mib=8;t.server.record.policy.rotate_mib=8;
 await t.logic.readStatus();assert.equal(t.logic.staleDraft.value,true);await t.logic.save();assert.equal(t.calls.filter(x=>x.method==='POST').length,0);
 t.logic.resetDraft();assert.equal(t.logic.draft.value.rotate_mib,8);assert.equal(t.logic.draftRevision.value,2);assert.equal(t.logic.dirty.value,false);
});
test('actual automatic component never retries a lost or foreign acknowledgement',async()=>{
 for(const mode of ['lost-reply','foreign-reply']){
  const t=automaticComponent(mode);await t.logic.readStatus(true);t.logic.draft.value.enabled=true;await t.logic.save();
  assert.equal(t.logic.uncertain.value,true);assert.equal(t.logic.known.value,false);assert.match(t.logic.error.value,/不会自动重试/);
  await t.logic.readStatus();await t.logic.save();assert.equal(t.calls.length,2);
  await t.logic.readStatus(true);assert.equal(t.calls.length,3);assert.equal(t.logic.uncertain.value,false);assert.equal(t.logic.known.value,true);assert.equal(t.logic.dirty.value,false);assert.equal(t.calls.filter(x=>x.method==='POST').length,1);assert.equal(t.logic.draftRevision.value,2);t.logic.draft.value.rotate_mib=4;assert.equal(t.logic.staleDraft.value,false);
 }
});
test('actual automatic component serializes double saves and ignores late or malformed reads',async()=>{
 const t=automaticComponent();await t.logic.readStatus(true);t.logic.draft.value.enabled=true;let reply;
 t.props.api=async(path,method,body)=>{t.calls.push({path,method,body});return new Promise(resolve=>{reply=resolve})};
 const first=t.logic.save();await Promise.resolve();await t.logic.save();assert.equal(t.calls.filter(x=>x.method==='POST').length,1);
 const result=automaticFixture();result.policy_revision=2;result.record.config_revision=2;result.policy.enabled=result.record.policy.enabled=true;reply(result);await first;assert.equal(t.logic.known.value,true);
 const late=automaticComponent();late.props.api=async()=>new Promise(resolve=>{reply=resolve});const pending=late.logic.readStatus(true);late.props.active=false;reply(automaticFixture());await pending;assert.equal(late.logic.applied.value,undefined);
 const bad=automaticComponent('bad-status');await bad.logic.readStatus(true);assert.equal(bad.logic.known.value,false);assert(bad.events.some(x=>x[0]==='blocked'&&x[1]===true));
});
test('an unknown automatic result also blocks a new manual rotation',async()=>{
 const parent=component();await parent.logic.refresh();parent.logic.automaticBlocked.value=true;await parent.logic.action('rotate');assert.equal(parent.calls.filter(x=>x.method==='POST').length,0);
 const child=automaticComponent();child.server.record.state='unknown';child.server.record.error_code='rotation_failed';await child.logic.readStatus(true);
 assert(child.events.some(x=>x[0]==='blocked'&&x[1]===true));assert.equal(child.calls.filter(x=>x.method==='POST').length,0);
 for(const version of ['2.3.0','2.4.1','v2.4.0','']){const old=automaticComponent('success',version);await old.logic.readStatus(true);assert.equal(old.calls.length,0)}
});

test('actual availability callback preserves unsaved drafts across tab switches',async()=>{
 assert.match(autoSource,/watch\(\(\)=>\[props\.active,props\.installed,props\.version\],availabilityChanged/);
 const t=automaticComponent();await t.logic.readStatus(true);t.logic.draft.value.rotate_mib=4;
 t.props.active=false;t.logic.availabilityChanged([false,true,'2.4.0'],[true,true,'2.4.0']);
 assert.equal(t.calls.length,1);assert.equal(t.logic.draft.value.rotate_mib,4);
 t.props.active=true;t.logic.availabilityChanged([true,true,'2.4.0'],[false,true,'2.4.0']);await new Promise(setImmediate);
 assert.equal(t.calls.length,2);assert.equal(t.logic.draft.value.rotate_mib,4);assert.equal(t.logic.applied.value.policy.rotate_mib,16);assert.equal(t.logic.draftRevision.value,1);assert.equal(t.logic.dirty.value,true);assert.equal(t.calls.filter(x=>x.method==='POST').length,0);
});
test('clean forms follow external revisions while edited forms retain their original revision',async()=>{
 const t=automaticComponent();await t.logic.readStatus(true);t.server.policy.rotate_mib=t.server.record.policy.rotate_mib=8;t.server.policy_revision=t.server.record.config_revision=2;
 await t.logic.readStatus();assert.equal(t.logic.draft.value.rotate_mib,8);assert.equal(t.logic.draftRevision.value,2);assert.equal(t.logic.dirty.value,false);
 t.logic.draft.value.rotate_mib=4;assert.equal(t.logic.staleDraft.value,false);await t.logic.save();assert.equal(t.calls.at(-1).body.expected_revision,2);assert.equal(t.logic.applied.value.policy_revision,3);
});
test('availability resets only a changed installation identity',async()=>{
 const t=automaticComponent();await t.logic.readStatus(true);t.logic.draft.value.rotate_mib=4;
 t.props.installed=false;t.logic.availabilityChanged([true,false,'2.4.0'],[true,true,'2.4.0']);assert.equal(t.logic.applied.value,undefined);assert.equal(t.logic.draft.value.rotate_mib,16);assert.equal(t.calls.length,1);
 t.props.installed=true;t.logic.availabilityChanged([true,true,'2.4.0'],[true,false,'2.4.0']);await new Promise(setImmediate);assert.equal(t.logic.known.value,true);assert.equal(t.logic.dirty.value,false);
});
test('incomplete or out-of-bound thresholds never create an uncertain mutation',async()=>{
 for(const value of [undefined,null,0,29,1.5]){
  const t=automaticComponent();await t.logic.readStatus(true);t.logic.draft.value.rotate_mib=value;assert.equal(t.logic.validDraft.value,false);await t.logic.save();assert.equal(t.calls.filter(x=>x.method==='POST').length,0);assert.equal(t.logic.uncertain.value,false);
 }
});

test('actual active callback prevents late GET success/error/finally from touching a fresh read',async()=>{
 for(const oldOutcome of ['resolve','reject']){
  const t=automaticComponent();await t.logic.readStatus(true);t.logic.draft.value.rotate_mib=4;const requests=[];
  t.props.api=async(path,method)=>{assert.equal(method,undefined);return new Promise((resolve,reject)=>requests.push({resolve,reject}))};
  const old=t.logic.readStatus();assert.equal(requests.length,1);
  t.props.active=false;t.logic.availabilityChanged([false,true,'2.4.0'],[true,true,'2.4.0']);
  t.props.active=true;t.logic.availabilityChanged([true,true,'2.4.0'],[false,true,'2.4.0']);assert.equal(requests.length,2);assert.equal(t.logic.reading.value,true);
  const stale=automaticFixture();stale.policy_revision=stale.record.config_revision=9;stale.policy.enabled=stale.record.policy.enabled=true;
  if(oldOutcome==='resolve')requests[0].resolve(stale);else requests[0].reject(Error('obsolete GET failure'));
  await old;assert.equal(t.logic.reading.value,true);assert.equal(t.logic.known.value,false);assert.equal(t.logic.error.value,'');assert.equal(t.logic.applied.value.policy_revision,1);
  requests[1].resolve(automaticFixture());await new Promise(setImmediate);assert.equal(t.logic.reading.value,false);assert.equal(t.logic.known.value,true);assert.equal(t.logic.applied.value.policy_revision,1);assert.equal(t.logic.draft.value.rotate_mib,4);assert.equal(t.logic.draftRevision.value,1);
 }
});
test('a hidden pending POST never overwrites observed state or clears a newer explicit write',async()=>{
 for(const oldOutcome of ['resolve','reject']){
  const t=automaticComponent();await t.logic.readStatus(true);t.logic.draft.value.enabled=true;const posts=[],calls=[];
  const current=automaticFixture();current.policy_revision=current.record.config_revision=2;current.policy.enabled=current.record.policy.enabled=true;
  t.props.api=async(path,method,body)=>{calls.push({path,method,body:structuredClone(body)});if(method==='POST')return new Promise((resolve,reject)=>posts.push({resolve,reject}));return structuredClone(current)};
  const old=t.logic.save();assert.equal(posts.length,1);assert.equal(t.logic.writing.value,true);
  t.props.active=false;t.logic.availabilityChanged([false,true,'2.4.0'],[true,true,'2.4.0']);assert.equal(t.logic.uncertain.value,true);
  t.props.active=true;t.logic.availabilityChanged([true,true,'2.4.0'],[false,true,'2.4.0']);await new Promise(setImmediate);
  assert.equal(posts.length,1);assert.equal(t.logic.known.value,true);assert.equal(t.logic.uncertain.value,false);assert.equal(t.logic.draftRevision.value,2);assert.equal(t.logic.dirty.value,false);
  t.logic.draft.value.rotate_mib=4;const next=t.logic.save();assert.equal(posts.length,2);assert.equal(t.logic.writing.value,true);assert.equal(calls.at(-1).body.expected_revision,2);
  if(oldOutcome==='resolve')posts[0].resolve({obsolete:'ignored without parsing'});else posts[0].reject(Error('obsolete POST failure'));
  await old;assert.equal(t.logic.writing.value,true);assert.equal(t.logic.error.value,'');assert.equal(t.logic.applied.value.policy_revision,2);
  current.policy_revision=current.record.config_revision=3;current.policy.rotate_mib=current.record.policy.rotate_mib=4;posts[1].resolve(structuredClone(current));await next;
  assert.equal(t.logic.writing.value,false);assert.equal(t.logic.applied.value.policy_revision,3);assert.equal(t.logic.known.value,true);assert.equal(t.logic.uncertain.value,false);
 }
});
test('version-only availability changes reset old draft and reinitialize supported installation',async()=>{
 const t=automaticComponent();await t.logic.readStatus(true);t.logic.draft.value.rotate_mib=4;
 t.props.version='2.3.0';t.logic.availabilityChanged([true,true,'2.3.0'],[true,true,'2.4.0']);assert.equal(t.logic.applied.value,undefined);assert.equal(t.logic.draft.value.rotate_mib,16);assert.equal(t.calls.length,1);
 t.props.version='2.4.0';t.logic.availabilityChanged([true,true,'2.4.0'],[true,true,'2.3.0']);await new Promise(setImmediate);assert.equal(t.logic.known.value,true);assert.equal(t.logic.dirty.value,false);assert.equal(t.logic.draftRevision.value,1);
});
