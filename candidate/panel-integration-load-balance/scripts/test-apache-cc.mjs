import {test} from "node:test";
import assert from "node:assert/strict";
import {readFileSync} from "node:fs";
import {createRequire} from "node:module";
import ts from "../web/node_modules/typescript/lib/typescript.js";
import {apacheBodyBuildInventory} from "../web/src/apacheBodyBuild.ts";

const vue=createRequire(new URL("../web/package.json",import.meta.url))("vue");
const read=name=>readFileSync(new URL("../"+name,import.meta.url),"utf8");
const source=read("web/src/ApacheCCEngine.vue");
const actual=source.slice(source.indexOf("const supported="),source.indexOf("</script>"));
const script=ts.transpileModule(actual,{compilerOptions:{target:ts.ScriptTarget.ES2022}}).outputText;
const ready={job_id:"a".repeat(32),state:"ready",build_only:true,architecture:"arm64",engine_version:"2.9.15-yz5",native_cc_version:"1.0.0",yajl_version:"2.1.0-debian5-yz1",crs_version:"4.30.0",apache_version:"2.4.68",integrity_verified:true,module_abi_validated:true,elf_hardening_validated:true,compiler_groups_collected:true,steps:[{time:"2026-11-03T04:00:00Z",message:"independently verified"}]};
const old={...ready,job_id:"b".repeat(32)};delete old.native_cc_version;
const inventory=(entries=[old,ready])=>({entries:structuredClone(entries),build_only:true,activation_requires_explicit_site_policy:true});
const settle=async()=>{await vue.nextTick();await new Promise(setImmediate);};

function component(api,overrides={}){
 const calls=[],cleanup=[];
 const props=vue.reactive({active:false,installed:true,version:"2.5.0",implementation:"2.5.0",parentBusy:false,settings:{body:{engine_job_id:old.job_id,sites:[]}},...overrides,api:async(...args)=>{calls.push(args);return api(...args);}});
 const scope=vue.effectScope();
 const logic=scope.run(()=>new Function("computed","ref","watch","onBeforeUnmount","props","emit","apacheBodyBuildInventory",script+"\nreturn {supported,known,reading,ready,error,refresh,chooseEngine};")
  (vue.computed,vue.ref,vue.watch,fn=>cleanup.push(fn),props,()=>{},apacheBodyBuildInventory));
 return {props,logic,calls,stop(){cleanup.forEach(fn=>fn());scope.stop();}};
}

test("CC inventory requires current native evidence and never upgrades a body-only row",()=>{
 assert.equal(apacheBodyBuildInventory(inventory()),true);
 for(const patch of [{native_cc_version:"1.0.0-alias"},{native_cc_version:"2.9.15-yz5"},{native_cc_version:true},{state:"queued"},{integrity_verified:false},{module_abi_validated:false},{compiler_groups_collected:false}])
  assert.equal(apacheBodyBuildInventory(inventory([{...ready,...patch}])),false,JSON.stringify(patch));
});

test("actual component fetches only on its exact installed active tab and needs explicit selection",async()=>{
 const t=component(async()=>inventory());
 try{
  await settle();assert.equal(t.calls.length,0);
  const body=structuredClone(vue.toRaw(t.props.settings.body));
  t.props.active=true;await settle();
  assert.equal(t.logic.known.value,true);assert.equal(t.logic.ready.value.length,1);
  assert.equal(t.props.settings.apache_cc,undefined);
  t.logic.chooseEngine(old.job_id);assert.equal(t.props.settings.apache_cc,undefined);
  t.props.parentBusy=true;t.logic.chooseEngine(ready.job_id);assert.equal(t.props.settings.apache_cc,undefined);
  t.props.parentBusy=false;t.logic.chooseEngine(ready.job_id);
  assert.deepEqual(t.props.settings.apache_cc,{engine_job_id:ready.job_id});assert.deepEqual(t.props.settings.body,body);
  assert.ok(t.calls.every(args=>args[0]==="/software/apache-waf/body-engines"&&args[1]===undefined));
 }finally{t.stop();}
 for(const values of [{installed:false},{installed:"true"},{version:"2.4.0",implementation:"2.4.0"},{version:"2.5.0",implementation:"2.4.0"},{version:"2.5.0-alias",implementation:"2.5.0-alias"}]){
  const t=component(async()=>inventory(),{active:true,...values});try{await settle();assert.equal(t.calls.length,0);t.logic.chooseEngine(ready.job_id);assert.equal(t.props.settings.apache_cc,undefined);}finally{t.stop();}
 }
});

test("failed or stale reads preserve the original CC reference and cannot enable a cached engine",async()=>{
 let finish;
 const t=component(()=>new Promise(resolve=>finish=resolve),{settings:{apache_cc:{engine_job_id:"c".repeat(32)}}});
 try{
  t.props.active=true;await settle();assert.equal(t.logic.reading.value,true);
  t.props.active=false;await settle();finish(inventory());await settle();
  assert.equal(t.logic.known.value,false);assert.equal(t.logic.ready.value.length,0);
  t.logic.chooseEngine(ready.job_id);assert.equal(t.props.settings.apache_cc.engine_job_id,"c".repeat(32));
 }finally{t.stop();}
 for(const value of [{},inventory([{...ready,integrity_verified:false}]),inventory([{...ready,native_cc_version:"1.1.0"}])]){
  const t=component(async()=>value,{active:true,settings:{apache_cc:{engine_job_id:"c".repeat(32)}}});
  try{await settle();assert.equal(t.logic.known.value,false);assert.equal(t.logic.ready.value.length,0);assert.ok(t.logic.error.value);t.logic.chooseEngine(ready.job_id);assert.equal(t.props.settings.apache_cc.engine_job_id,"c".repeat(32));}finally{t.stop();}
 }
});
