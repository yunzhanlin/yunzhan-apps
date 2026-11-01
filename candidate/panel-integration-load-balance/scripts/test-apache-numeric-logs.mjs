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
 const logic=new Function("bindings","with(bindings){"+actual+";return{inventory,known,unknown,error,receipt,reading,writing,confirming,supported,blocked,refresh,action,exportSnapshot};}")(bindings);
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
 assert(source.includes("当前页提供手动维护"));assert(!source.includes("setInterval"));assert(!source.includes("onMounted("));
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
