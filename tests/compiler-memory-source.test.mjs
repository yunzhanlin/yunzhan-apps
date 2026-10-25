import test from'node:test';import assert from'node:assert/strict';import fs from'node:fs';import path from'node:path';import{createHash}from'node:crypto';import{fileURLToPath}from'node:url';import{spawnSync}from'node:child_process';
import{compilerMemoryCIScope,verifyCompilerMemoryCISource,compilerMemoryCIArguments}from'../tools/run-compiler-memory-ci.mjs';
const root=fileURLToPath(new URL('..',import.meta.url)),scope='panel-integration-compiler-memory/',parent='panel-integration-build-pressure/';
const read=n=>fs.readFileSync(root+n),json=n=>JSON.parse(read(n)),sha=b=>createHash('sha256').update(b).digest('hex'),report=json('registry/compiler-memory-core.json');

test('exact1934 archive-bound members include1469 Go files without private QA, binaries, credentials, overlays or unfinished L4',()=>{
 const raw=read(scope+'source-sha256.json'),v=JSON.parse(raw);
 assert.equal(sha(raw),report.export.source_index_sha256);assert.equal(sha(read(scope+'release-source-inputs.json')),report.export.release_index_sha256);
 assert.equal(v.release.frozen_inputs_sha256,'1976023758cc006612e897538cad1af1b5d57332fa8a32a1d130fc546b223d15');
 assert.deepEqual(v.test_overrides,{});assert.equal(Object.keys(v.files).length,1934);assert.equal(Object.keys(v.files).filter(n=>n.endsWith('.go')).length,1469);
 assert.deepEqual(json(scope+'release-source-inputs.json'),{...v.release,files:v.files});
 for(const[n,h]of Object.entries(v.files)){
  assert.equal(path.posix.normalize(n),n);assert(!path.isAbsolute(n)&&!n.split('/').some(v=>['..','.git','.local','node_modules'].includes(v)));
  assert(!n.startsWith('internal/loadbalancestream/'));const s=fs.lstatSync(root+scope+n);assert(s.isFile()&&!s.isSymbolicLink()&&s.nlink===1&&s.size<=2<<20);
  assert.equal(sha(read(scope+n)),h,n);
 }
});
test('four exact original members and seven new implementation/test files are the complete F52 delta',()=>{
 const before=json(parent+'source-sha256.json'),after=json(scope+'source-sha256.json');
 assert.equal(sha(read(parent+'source-sha256.json')),'6db26510bf937b06b8f152bbe4aa151d04ca1280fdf46847a1826dac44d94f6a');
 assert.deepEqual(Object.keys(before.files).filter(n=>before.files[n]!==after.files[n]),report.changed_source_members);
 assert.deepEqual(Object.keys(after.files).filter(n=>!before.files[n]),report.added_source_members);assert(!Object.keys(before.files).some(n=>!after.files[n]));
 for(const[n,h]of Object.entries(before.files))if((n.endsWith('.go')&&n!=='internal/executor/install_linux.go')||['go.mod','go.sum','packaging/build-release.sh','web/package-lock.json','web/src/App.vue','web/src/FileManager.vue','web/src/mobileDelivery.ts'].includes(n))assert.equal(after.files[n],h,n);
 assert.equal(report.production_Go_existing_changes,1);assert.equal(report.production_Go_added,3);assert.equal(report.added_Go_tests,4);
});
function unitSettings(text){
 const settings={};let section;for(const line of text.split('\n').map(v=>v.trim())){if(!line||line.startsWith('#'))continue;if(line.startsWith('[')){section=line;continue;}const i=line.indexOf('=');assert(i>0);const key=section+line.slice(0,i);assert(!Object.hasOwn(settings,key));settings[key]=line.slice(i+1);}
 return settings;
}
test('one GiB finite policy retains every other original unit resource, command and sandbox field',()=>{
 const old=unitSettings(read(parent+'dev/panel-install@.service').toString()),now=unitSettings(read(scope+'dev/panel-install@.service').toString());
 assert.deepEqual(now,{...old,'[Service]MemoryHigh':'1G','[Service]MemoryMax':'1G'});
 assert.equal(sha(read(scope+'dev/panel-install@.service')),'bf2432e1084dce9629be620dfab2ed47995c9bbfa86a70285990f4d6fb1cd947');
 const p=report.policy;assert.equal(p.new_finite_installer_memory_bytes,1073741824);assert.equal(p.existing_service_reserve_bytes,536870912);assert.equal(p.new_large_build_request_minimum_available_bytes,1610612736);
 assert.equal(p.swap_limit_bytes,0);assert.equal(p.task_limit,512);assert.equal(p.timeout_minutes,300);assert(p.no_controlgroup_limit_or_counter_writes&&p.no_host_file_cache_or_slab_credit);
 const env={...process.env};delete env.NODE_TEST_CONTEXT;
 const v=spawnSync(process.execPath,['--test','--test-reporter=tap','scripts/test-runtime-build-pressure.mjs'],{cwd:root+scope,env,encoding:'utf8',timeout:30000,maxBuffer:2<<20});
 assert.equal(v.status,0,v.stdout+v.stderr);for(const x of['# tests 4','# pass 4','# fail 0','# skipped 0'])assert(v.stdout.includes(x));
});
test('source-bound compiler flags, actual kernel identity, conservative own-charge and pre-ledger admission remain mandatory',()=>{
 const gc=read(scope+'internal/executor/runtime_php_compiler_gc.go').toString(),kernel=read(scope+'internal/executor/runtime_php_memory_admission_linux.go').toString(),memory=read(scope+'internal/executor/runtime_php_memory_admission.go').toString(),install=read(scope+'internal/executor/install_linux.go').toString();
 assert(gc.includes('const runtimePHPCompilerGCFlags = "'+report.policy.fixed_CFLAGS+'"')&&gc.includes('r != official')&&gc.includes('r.SHA256 != spec.archiveSHA'));
 assert(!/-O[01](?:\s|")/u.test(gc));
 for(const text of['os.OpenRoot("/sys/fs/cgroup")','unix.CGROUP2_SUPER_MAGIC','decodeRuntimeCompilerCgroup','runtimePHPCompilerMemoryFootprint','owned.NonReclaimable','runtimePHPCompilerMemoryAncestorOwned'])assert(kernel.includes(text),text);
 assert(memory.includes('values["anon"] + values["shmem"]')&&!memory.includes('values["anon"] + values["shmem"] + values["kernel"]'));
 assert(install.includes('admitRuntimePHPHostMemory(known)')&&install.includes('admitRuntimePHPWorkerMemory(r)')&&install.includes('admitRuntimePHPWorkerMemory(release)')&&install.includes('debug.FreeOSMemory()'));
 const build=install.slice(install.indexOf('func buildCommand('));assert(build.indexOf('admitRuntimePHPWorkerMemory')<build.indexOf('beginRuntimeCompilerScope()'));
 assert(!/WriteFile|O_WRONLY|O_RDWR|memory\.reclaim|drop_caches/u.test(kernel));
});
test('all original37 CI jobs remain byte-exact and the38th mandatory workflow has no bypass',()=>{
 for(const[n,h]of Object.entries(report.original37_workflow_files))assert.equal(sha(read('.github/workflows/'+n)),h,n);
 const text=read('.github/workflows/compiler-memory.yml').toString();
 assert.deepEqual(text.match(/^  [a-z0-9_-]+:$/gm),['  push:','  pull_request:','  compiler-memory-contracts-linux-amd64:']);
 for(const value of['timeout-minutes: 25','node --test tests/compiler-memory-source.test.mjs','go test -race ./internal/executor',"'^TestRuntimePHPCompiler(GC|Memory)'",'test -p 1 ./... -count=1','go vet ./...','test_runtime_install_budget.py','--ignore-scripts'])assert(text.includes(value),value);
 assert(!/continue-on-error|--overlay|reset-failed|TestNone/u.test(text));
});
test('actual OOM counters and complete native objects are component proof, never installed-runtime or all50 acceptance',()=>{
 for(const v of Object.values(report.native_compiler_components)){
  assert(v.actual_native_peak_bytes>0&&v.actual_native_peak_bytes<=1073741824);assert.equal(v.native_Zend_objects.length,2);
  assert(v.native_Zend_objects.every(o=>o.original_execution_functions_verified&&o.bytes>0&&/^[a-f0-9]{64}$/u.test(o.sha256)));
  for(const key of['oom','oom_kill','oom_group_kill'])assert.equal(v.memory_events_before[key]+v.memory_events_after[key],0);
  assert(v.all_owned_children_reaped&&v.exact_original_O2_and_all_extensions&&v.normal_runtime_install_or_application_acceptance===false);
 }
 assert.equal(report.native_compiler_components.php83.memory_events_after.max,461);
 assert(report.obsolete768MiB_native_negative.passed&&!report.obsolete768MiB_native_negative.compiler_or_source_script_invoked&&!report.obsolete768MiB_native_negative.build_log_created);
 for(const value of Object.values(report.original_failed_cases))assert(value===true||value===0);
 assert.equal(report.portable_memory_models.top_level_race_tests_passed,12);
 assert(report.business_preservation.original600_second_windows_not_extended_or_bridged&&report.business_preservation.neither_table_projection_nor_generic_audit_or_scheduler_exemption);
 for(const v of Object.values(report.normal_programme_builds)){assert.equal(v.original_build_exit,0);assert(v.core_panel_and_start_guard_byte_identical_to_F52&&v.only_executor_programme_changed);assert(!v.signed&&!v.installed&&!v.all50_commercial);}
 for(const key of['programme_signed','normal_upgrade_accepted','new_Main_PHP_install_accepted','all50_commercial'])assert.equal(report[key],false);
});
test('all50 original signed app manifests, catalogue and application trust remain unchanged',()=>{
 for(const[n,h]of Object.entries({'dist/catalog-v1.json':'247c8db6cc762413c0779f8cb8a251b16d01b641b109981f084076c20f104813','signatures/catalog-v1.sig':'4828f4a705f62ca1c8e2380528e0b1d65719e0be37c561790343862c60936727','signatures/catalog-v1.bundle.json':'deb1a606c402933f40b772c920de3396f2b6c8d6c910b581c4acef6b7f6b7f25','signatures/catalog-v1.pub.pem':'659ea4edcecaf23a586e2ff371616fde5f6ee7c219fb70fa978816e2b10acf75'}))assert.equal(sha(read(n)),h,n);
 const catalog=json('dist/catalog-v1.json');assert.equal(catalog.apps.length,50);for(const app of catalog.apps)assert.equal(sha(read('dist/apps/'+app.id+'/'+app.version+'/manifest.json')),app.sha256);
});
test('new full-suite gate runs the exact already-corrected1934 source members directly and refuses filters, overlays and foreign scopes',()=>{
 const index=json(scope+'source-sha256.json');assert.deepEqual(verifyCompilerMemoryCISource(root+scope.slice(0,-1)),index);
 assert.equal(compilerMemoryCIScope.files,1934);assert.equal(compilerMemoryCIScope.Go,1469);
 assert.equal(sha(read('tools/run-https-fixture-ci.mjs')),'948fb862a143078e1428fc9d4a4ca18397a134938bef96f61ea24ae03bc1664e');
 assert.throws(()=>verifyCompilerMemoryCISource(root+parent.slice(0,-1)));assert.throws(()=>verifyCompilerMemoryCISource(root+scope));
 assert.deepEqual(compilerMemoryCIArguments(['test','-p','1','./...','-count=1']),['test','-p','1','./...','-count=1']);
 for(const args of[['test','./internal/executor'],['test','-p','1','./...'],['test','-p','1','./...','-count=1','-run=TestNone'],['test','-overlay=foreign.json','-p','1','./...','-count=1'],['test','-p','1','./...','-count=0']])assert.throws(()=>compilerMemoryCIArguments(args));
 const workflow=read('.github/workflows/compiler-memory.yml').toString();assert(workflow.includes('$GITHUB_WORKSPACE/tools/run-compiler-memory-ci.mjs'));assert(!workflow.includes('run-https-fixture-ci.mjs'));
});
