import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
const root=fileURLToPath(new URL('..',import.meta.url)), scope='panel-integration-build-pressure/', parent='panel-integration-native-queue-observation/';
const read=n=>fs.readFileSync(root+n), json=n=>JSON.parse(read(n)), sha=b=>createHash('sha256').update(b).digest('hex');
const report=json('registry/build-pressure-core.json');

test('exact1927 archive-bound members retain every1462 Go file and exclude unfinished L4, binaries and private QA',()=>{
 const raw=read(scope+'source-sha256.json'),value=JSON.parse(raw);
 assert.equal(sha(raw),report.export.source_index_sha256);
 assert.equal(sha(read(scope+'release-source-inputs.json')),report.export.release_index_sha256);
 assert.equal(value.release.frozen_inputs_sha256,'e0c8323c6147bacc28caeb3dd8b57513170c66209af807104a18ddf6137ea45e');
 assert.deepEqual(value.test_overrides,{});assert.equal(Object.keys(value.files).length,1927);assert.equal(Object.keys(value.files).filter(n=>n.endsWith('.go')).length,1462);
 assert.deepEqual(json(scope+'release-source-inputs.json'),{...value.release,files:value.files});
 assert(!Object.keys(value.files).some(n=>n.startsWith('internal/loadbalancestream/')));
 for(const[n,digest]of Object.entries(value.files)){
  assert.equal(path.posix.normalize(n),n);assert(!path.isAbsolute(n)&&!n.split('/').some(v=>['..','.git','.local','node_modules'].includes(v)));
  const file=root+scope+n,info=fs.lstatSync(file);assert(info.isFile()&&!info.isSymbolicLink()&&info.nlink===1&&info.size<=2<<20);
  assert.equal(sha(fs.readFileSync(file)),digest,n);
 }
});
test('only six explicit policy/presentation members and one mandatory gate differ from F51; all Go including tests stays exact',()=>{
 const raw=read(parent+'source-sha256.json'),before=JSON.parse(raw),after=json(scope+'source-sha256.json');
 assert.equal(sha(raw),'c5f1a42bf64fe595397fe06a6ad9524e3eab076388e3e9e8a0cb01e57d2e0de0');
 assert.deepEqual(Object.keys(before.files).filter(n=>before.files[n]!==after.files[n]),report.changed_source_members);
 assert.deepEqual(Object.keys(after.files).filter(n=>!before.files[n]),['scripts/test-runtime-build-pressure.mjs']);
 assert(!Object.keys(before.files).some(n=>!after.files[n]));
 for(const[n,digest]of Object.entries(before.files))if(n.endsWith('.go')||['go.mod','go.sum'].includes(n))assert.equal(after.files[n],digest,n);
 for(const n of['web/package.json','web/package-lock.json','web/src/App.vue','web/src/FileManager.vue','web/src/mobileDelivery.ts','web/src/AppModuleReport.vue'])assert.equal(after.files[n],before.files[n],n);
});
test('unit changes only the early soft threshold; hard ceiling, swap, tasks, command and all original sandbox fields remain exact',()=>{
 const old=read(parent+'dev/panel-install@.service').toString(),current=read(scope+'dev/panel-install@.service').toString();
 const replacement='# PHP\'s single compiler can need more than 640 MiB of anonymous working memory.\n# Early high-limit reclaim with zero swap can stall it below the hard ceiling.\n# Keep the SAME finite 768 MiB hard cap, swap policy and all sandbox boundaries.\nMemoryHigh=768M\n';
 assert.equal(current,old.replace('MemoryHigh=640M\n',replacement));
 assert.equal(sha(Buffer.from(current)),'cfd04fca2d44050e3ee8a8de9b3a0d5d74f6f8ab9dd1120e4c8c20da540d2266');
 assert.deepEqual(report.policy,{old_soft_limit_bytes:671088640,new_soft_limit_bytes:805306368,unchanged_hard_limit_bytes:805306368,unchanged_swap_limit_bytes:0,unchanged_task_limit:512,unchanged_timeout_minutes:300,all_original_sandbox_and_writable_paths_preserved:true,live_existing_resource_limits_not_changed:true});
 const oldAssertions=read(parent+'packaging/test_runtime_install_budget.py').toString().split('\n').filter(n=>n.trim().startsWith('self.assert'));
 const updated=read(scope+'packaging/test_runtime_install_budget.py').toString();
 for(const line of oldAssertions)assert(updated.includes(line.replace('settings["MemoryHigh"], "640M"','settings["MemoryHigh"], "768M"')),line);
});
test('normal snapshot builder adds the pressure gate without removing or altering any original build gate',()=>{
 const before=read(parent+'packaging/build-release.sh').toString(),after=read(scope+'packaging/build-release.sh').toString();
 const line='(cd "$BUILD_ROOT" && /opt/homebrew/bin/node --test scripts/test-runtime-build-pressure.mjs) 2>&1 | tee -a "$STAGE/$NAME/BUILD_CHECKS.txt"\n';
 assert.equal(after.split(line).length,2);assert.equal(after.replace(line,''),before);
 const env={...process.env};delete env.NODE_TEST_CONTEXT;
 const result=spawnSync(process.execPath,['--test','--test-reporter=tap','scripts/test-runtime-build-pressure.mjs'],{cwd:root+scope,env,encoding:'utf8',timeout:30000,maxBuffer:2<<20});
 assert.equal(result.status,0,result.stdout+result.stderr);assert(!result.error&&!result.signal);
 for(const text of['# tests 4','# pass 4','# fail 0','# skipped 0'])assert(result.stdout.includes(text),text);
});
test('all original36 workflows remain byte-exact and the37th source-contract job cannot bypass checks',()=>{
 for(const[name,digest]of Object.entries(report.original36_workflow_files))assert.equal(sha(read('.github/workflows/'+name)),digest,name);
 const workflow=read('.github/workflows/build-pressure.yml').toString();
 assert.deepEqual(workflow.match(/^  [a-z0-9_-]+:$/gm),['  push:','  pull_request:','  runtime-build-pressure-contracts-linux-amd64:']);
 for(const text of['timeout-minutes: 25','node --test tests/build-pressure-source.test.mjs',"-p 'test_runtime_install_budget.py'",'scripts/test-runtime-build-pressure.mjs','--ignore-scripts','scripts/test-store-search.mjs scripts/test-store-updates.mjs scripts/test-software-state.mjs'])assert(workflow.includes(text),text);
 assert(!/continue-on-error|--overlay|reset-failed|TestNone/.test(workflow));
});
test('original compiler and old immutable candidate remain failed; portable archives are not native installed or commercial acceptance',()=>{
 const old=report.original_Main_compiler_observation;assert.equal(old.application_result,false);assert.equal(old.working_set_bytes,681811968);assert.equal(old.anonymous_bytes,670130176);assert.equal(old.oom_kills,0);
 for(const key of['original_native_and_Core_failure_preserved','original_application_job_not_replayed','new_runtime_never_published','old_sites_bindings_NSS_configs_runtime_bytes_and_programme_lifetimes_unchanged','original600_second_SQL_window_not_extended_or_bridged'])assert.equal(old[key],true,key);
 assert.equal(report.original_failed_candidate.inputs,'272f96993a1eef6c3fc925f318b1f4fb0e67bdad5c20f716ff5ae119e3e2a7d8');assert.equal(report.original_failed_candidate.both_normal_build_exits,1);assert(report.original_failed_candidate.original_result_not_relabelled);
 const previous=json('registry/native-queue-observation-core.json');
 for(const[arch,value]of Object.entries(report.normal_programme_builds)){
  assert.equal(value.original_build_exit,0);assert.equal(value.all_three_programmes_byte_identical_to_F51,true);assert.deepEqual(value.programmes,previous.normal_programme_builds[arch].programmes);
  assert(/^[a-f0-9]{64}$/.test(value.archive_sha256));assert.equal(value.unit_sha256,'cfd04fca2d44050e3ee8a8de9b3a0d5d74f6f8ab9dd1120e4c8c20da540d2266');
  assert.equal(value.eager_javascript_bytes,1174558);assert(value.eager_javascript_bytes<=1200000);assert(!value.signed&&!value.installed&&!value.all50_commercial);
 }
 for(const key of['programme_signed','normal_upgrade_accepted','new_Main_PHP_install_accepted','all50_commercial'])assert.equal(report[key],false,key);
 assert.equal(report.source_overrides,0);assert.equal(report.production_Go_changes,0);
});
test('all50 existing signed application manifests and official application trust remain unchanged',()=>{
 for(const[name,digest]of Object.entries({'dist/catalog-v1.json':'247c8db6cc762413c0779f8cb8a251b16d01b641b109981f084076c20f104813','signatures/catalog-v1.sig':'4828f4a705f62ca1c8e2380528e0b1d65719e0be37c561790343862c60936727','signatures/catalog-v1.bundle.json':'deb1a606c402933f40b772c920de3396f2b6c8d6c910b581c4acef6b7f6b7f25','signatures/catalog-v1.pub.pem':'659ea4edcecaf23a586e2ff371616fde5f6ee7c219fb70fa978816e2b10acf75'}))assert.equal(sha(read(name)),digest,name);
 const catalog=json('dist/catalog-v1.json');assert.equal(catalog.apps.length,50);for(const app of catalog.apps)assert.equal(sha(read('dist/apps/'+app.id+'/'+app.version+'/manifest.json')),app.sha256);
});
