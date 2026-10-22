import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {apacheBodyBuildRow,apacheBodyBuildInventory,apacheBodyQueueReply} from '../web/src/apacheBodyBuild.ts';
const id='a'.repeat(32),read=path=>readFileSync(new URL('../'+path,import.meta.url),'utf8');
const ready={job_id:id,state:'ready',build_only:true,architecture:'amd64',engine_version:'2.9.15-yz5',yajl_version:'2.1.0-debian5-yz1',crs_version:'4.30.0',apache_version:'2.4.68',integrity_verified:true,module_abi_validated:true,elf_hardening_validated:true,compiler_groups_collected:true,steps:[{time:'2026-10-11T00:00:00Z',message:'sealed'}]};
test('ready is all four verified facts and exact Apache, not Nginx or an old patch',()=>{
 assert.equal(apacheBodyBuildRow(ready,id),true);assert.equal(apacheBodyBuildRow({...ready,architecture:'arm64'},id),true);
 for(const patch of [{job_id:'../bad'},{job_id:123},{build_only:false},{state:'invented'},{architecture:'darwin'},{engine_version:'2.9.15-yz3'},{engine_version:'2.9.15-yz4'},{engine_version:'3.0.17-yz1'},{yajl_version:'2.1.0'},{crs_version:'latest'},{apache_version:'2.4.67'},{error:'unresolved'},{integrity_verified:false},{module_abi_validated:false},{elf_hardening_validated:false},{compiler_groups_collected:false},{elf_hardening_validated:'true'},{steps:null},{steps:Array(49).fill(ready.steps[0])},{steps:[{time:'unknown',message:'done'}]},{steps:[{time:ready.steps[0].time,message:''}]}])assert.equal(apacheBodyBuildRow({...ready,...patch},id),false,JSON.stringify(patch));
 assert.equal(apacheBodyBuildRow(ready,'b'.repeat(32)),false);
 assert.equal(apacheBodyBuildRow({job_id:id,state:'queued',build_only:true,steps:[]},id),true);
 assert.equal(apacheBodyBuildRow({job_id:id,state:'failed',build_only:true,steps:[]},id),false);
 assert.equal(apacheBodyBuildRow({job_id:id,state:'failed',build_only:true,error:'owned failure',steps:[]},id),true);
});
test('unknown and partial inventories never become empty or stale verified rows',()=>{
 const inventory={entries:[ready],build_only:true,activation_requires_explicit_site_policy:true};
 assert.equal(apacheBodyBuildInventory(inventory),true);assert.equal(apacheBodyBuildInventory({...inventory,entries:[]}),true);
 for(const patch of [{entries:null},{entries:[ready,ready]},{entries:[{...ready,compiler_groups_collected:false}]},{entries:Array(193).fill(ready)},{build_only:false},{activation_requires_explicit_site_policy:false}])assert.equal(apacheBodyBuildInventory({...inventory,...patch}),false);
 for(const out of [null,{},[],{job_id:'../bad'},{job_id:id,command:'caller'}])assert.equal(apacheBodyQueueReply(out),false);
 assert.equal(apacheBodyQueueReply({job_id:id}),true);
});
test('retained YZ4 inventory is distinct, closed and never current readiness',()=>{
 const legacy={...ready,job_id:'b'.repeat(32),state:'retained_unsupported',engine_version:'2.9.15-yz4',error:'retained only, cannot enable',historical_integrity_verified:true,integrity_verified:false,module_abi_validated:false,elf_hardening_validated:false,compiler_groups_collected:false};
 assert.equal(apacheBodyBuildRow(legacy),true);
 assert.equal(apacheBodyBuildInventory({entries:[ready,legacy],build_only:true,activation_requires_explicit_site_policy:true}),true);
 for(const patch of [{state:'ready'},{engine_version:'2.9.15-yz3'},{engine_version:'2.9.15-yz5'},{historical_integrity_verified:false},{historical_integrity_verified:'true'},{error:''},{architecture:'unknown'},{integrity_verified:true},{module_abi_validated:true},{elf_hardening_validated:true},{compiler_groups_collected:true},{yajl_version:'2.1.0'},{crs_version:'latest'},{apache_version:'2.4.67'}])assert.equal(apacheBodyBuildRow({...legacy,...patch}),false,JSON.stringify(patch));
 assert.equal(apacheBodyBuildRow({...ready,historical_integrity_verified:true}),false);
 const view=read('web/src/ApacheBodyBuild.vue');assert.match(view,/retained_unsupported:"旧版程序保留，当前不能启用"/);
 assert.match(view,/旧版 YZ4 不会被标成新版或自动启用/);
});
test('the lazy scoped workspace only mutates on explicit actions and preserves an uncertain queue key',()=>{
 const view=read('web/src/ApacheBodyBuild.vue');
 assert.match(read('web/src/WafWorkspace.vue'),/<ApacheBodyBuild :api="api" :active="tab==='apache-body-build'"/);
 assert.match(view,/pendingKey\.value \|\|= randomId\(\)/);assert.match(view,/"POST",\{\},pendingKey\.value/);
 assert.match(view,/apacheBodyQueueReply\(out\)/);assert.match(view,/apacheBodyBuildRow\(out,id\)/);assert.match(view,/apacheBodyBuildInventory\(out\)/);
 assert.match(view,/ticket===epoch/);assert.match(view,/onBeforeUnmount\(\(\)=>\{disposed=true;epoch\+\+;stopObserving\(\)/);
 assert.match(view,/<el-table v-if="known"/);assert.match(view,/v-if="selected && known"/);assert.match(view,/库存尚不可核实（不是零个引擎）/);
 assert.match(view,/85% CPU \/ 640 MiB/);assert.match(view,/没有安装应用或启用网站/);assert.match(view,/当前不能通过本页启用/);
 const watch=view.split('watch(()=>props.active,')[1].split('onBeforeUnmount')[0];assert.doesNotMatch(watch,/POST|build\(|cancel\(/);
 assert.doesNotMatch(view,/setInterval|\/software\/nginx-waf|body-log\/|selectBodyEngine/);
});
test('normal package gates, independent APIs, hardening and permanent cancellation barriers are included',()=>{
 assert.match(read('packaging/build-release.sh'),/test-apache-body-build\.mjs/);
 for(const file of ['internal/core/apache_waf.go','internal/executor/apache_waf_linux.go'])assert.match(read(file),/apacheBodyEngineRoutes\(m\)/);
 const core=read('internal/core/apache_body_engine.go');assert.match(core,/apache_body_build/);assert.match(core,/role != "admin"/);assert.match(core,/out\.State == "failed" && out\.Error == ""/);
 const worker=read('internal/core/apache_body_engine_worker.go');for(const flag of ['IntegrityVerified','ABIValidated','HardeningValidated','CompilerCollected'])assert.ok(worker.includes('!result.'+flag));
 const native=read('internal/executor/apache_body_native_linux.go');assert.match(native,/verifyApacheBodyWorkerCapabilities\(\)/);assert.match(native,/apacheBodyNotCanceled\(id\)/);assert.match(native,/probeApacheBodyELF/);
 const json=read('internal/executor/apache_body_json.go');
 assert.match(json,/keys\[folded\]/);assert.match(json,/strings\.ToLower\(name\)/);
 assert.match(json,/apacheBodyValidateJSON\(b, 64<<10, 4096, 6, known\)/);
 assert.match(read('internal/executor/apache_body_site_edit_linux.go'),/apacheBodyValidateJSON\(data, 512<<10, 32768, 16, nil\)/);
});
