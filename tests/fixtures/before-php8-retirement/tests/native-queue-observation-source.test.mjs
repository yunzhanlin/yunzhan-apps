import test from'node:test';import assert from'node:assert/strict';import fs from'node:fs';import path from'node:path';import{createHash}from'node:crypto';import{fileURLToPath}from'node:url';import{spawnSync}from'node:child_process';
const root=fileURLToPath(new URL('..',import.meta.url)),scope='panel-integration-native-queue-observation/',parent='panel-integration-mobile-delivery-links/',read=n=>fs.readFileSync(root+n),json=n=>JSON.parse(read(n)),sha=b=>createHash('sha256').update(b).digest('hex'),report=json('registry/native-queue-observation-core.json');
test('new source is exactly1926 archive-bound files and1462 Go files with no overlay or unfinished L4 code',()=>{
 const raw=read(scope+'source-sha256.json'),v=JSON.parse(raw);assert.equal(sha(raw),report.export.source_index_sha256);assert.equal(sha(read(scope+'release-source-inputs.json')),report.export.release_index_sha256);
 assert.equal(v.release.frozen_inputs_sha256,'482f93d5ae54f5a8e888988a8b2a13065cafdb9a91df643392ae4020f22deb28');
 assert.deepEqual(v.test_overrides,{});assert.equal(Object.keys(v.files).length,1926);assert.equal(Object.keys(v.files).filter(n=>n.endsWith('.go')).length,1462);
 assert.deepEqual(json(scope+'release-source-inputs.json'),{...v.release,files:v.files});
 assert(!Object.keys(v.files).some(n=>n.startsWith('internal/loadbalancestream/')));
 for(const[n,h]of Object.entries(v.files)){const p=root+scope+n,s=fs.lstatSync(p);assert(path.posix.normalize(n)===n&&!path.isAbsolute(n)&&!n.split('/').some(v=>['..','.git','.local','node_modules'].includes(v)));assert(s.isFile()&&!s.isSymbolicLink()&&s.nlink===1&&s.size<=2<<20);assert.equal(sha(fs.readFileSync(p)),h,n);}
});
test('only exact original IDS query grouping and one mandatory build gate differ from the immutable F50 export',()=>{
 const oldRaw=read(parent+'source-sha256.json'),old=JSON.parse(oldRaw),v=json(scope+'source-sha256.json');assert.equal(sha(oldRaw),'53a75994e6e1e566f9a1687146c72102ebdc80ee069262c2cf43bcbcb609c4e5');
 assert.deepEqual(Object.keys(old.files).filter(n=>old.files[n]!==v.files[n]),['internal/executor/program_upgrade_ids_linux.go','packaging/build-release.sh']);
 assert.deepEqual(Object.keys(v.files).filter(n=>!old.files[n]),['internal/executor/program_upgrade_ids_units_linux.go','internal/executor/program_upgrade_ids_units_linux_test.go','internal/executor/program_upgrade_ids_units_native_qa_linux_test.go','scripts/test-native-queue-unit-snapshot.mjs']);
 assert(!Object.keys(old.files).some(n=>!v.files[n]));
 for(const n of['internal/executor/program_upgrade_queues_linux.go','internal/executor/memcached_unix_upgrade_linux.go','web/src/FileManager.vue','web/src/AppModuleReport.vue','web/src/mobileDelivery.ts','web/package.json','web/package-lock.json'])assert.equal(v.files[n],old.files[n],n);
 const line='(cd "$BUILD_ROOT" && /opt/homebrew/bin/node --test scripts/test-native-queue-unit-snapshot.mjs) 2>&1 | tee -a "$STAGE/$NAME/BUILD_CHECKS.txt"\n',build=read(scope+'packaging/build-release.sh').toString();
 assert.equal(build.split(line).length,2);assert.equal(build.replace(line,''),read(parent+'packaging/build-release.sh').toString());
});
test('the old35 CI jobs remain byte exact and this36th job is independent with unchanged bounds',()=>{
 for(const[n,h]of Object.entries(report.original35_workflow_files))assert.equal(sha(read('.github/workflows/'+n)),h);
 assert.equal(report.original35_workflow_files['verify.yml'],'3682cf6cbb573d1ca20d2373265fc2b12b6982af9449aac828827c354b7e09a3');
 const text=read('.github/workflows/native-queue-observation.yml').toString();
 assert.deepEqual(text.match(/^  [a-z0-9_-]+:$/gm),['  push:','  pull_request:','  native-queue-unit-contracts-linux-amd64:']);
 for(const value of['timeout-minutes: 25','node --test tests/native-queue-observation-source.test.mjs','node --test scripts/test-native-queue-unit-snapshot.mjs','test -race ./internal/executor','go vet ./internal/executor'])assert(text.includes(value),value);
 assert(!/continue-on-error|--overlay|reset-failed|TestNone/.test(text));
});
test('mandatory source gate preserves original per-unit predicates and complete5s reader before a normal build',()=>{
 const env={...process.env};delete env.NODE_TEST_CONTEXT;
 const result=spawnSync(process.execPath,['--test','--test-reporter=tap','scripts/test-native-queue-unit-snapshot.mjs'],{cwd:root+scope,env,encoding:'utf8',timeout:30000,maxBuffer:2<<20});
 assert.equal(result.status,0,result.stdout+result.stderr);assert(!result.signal&&!result.error);
 for(const line of['# tests 4','# pass 4','# fail 0','# skipped 0'])assert(result.stdout.includes(line),line);
});
test('both actual native source observations contain all11 top-level83 tests and all103 business fields with no app writes',()=>{
 for(const[arch,v]of Object.entries(report.actual_native_readonly_source_qualification)){
  assert(['amd64','arm64'].includes(arch));assert.equal(v.source_subset_sha256,'56e43162b51c5537a6498108e35d85ec01f297a52e4c78d9f8f190250d214af5');assert.equal(v.top_level,11);assert.equal(v.including_subtests,83);assert.equal(v.failures,0);assert.equal(v.skips,0);
  for(const k of['all103_full_business_and_nine_monitor_columns_preserved','original_NSS_programmes20_modules_and_sites_preserved','zero_byte_original_lock_identities_and_bytes_preserved','previous_false_aggregate_retained'])assert.equal(v[k],true,k);
  assert.equal(v.application_operations,0);assert.equal(v.actual_global5s_observations.length,3);assert(/^[a-f0-9]{64}$/.test(v.original_root_proof_sha256));
 }
 assert.equal(report.global_native_queue_deadline_seconds,5);assert.equal(report.original_unit_count,3);assert.equal(report.all_original_properties_per_unit,13);assert.equal(report.original_per_unit_limit_bytes,4096);
});
test('the original failed AMD F50 install stays false and new portable archives are not signatures or installed acceptance',()=>{
 assert.deepEqual(report.original_failed_F50_AMD_install,{ok:false,preflight_exit:0,install_exit:1,proof_sha256:'93cc3c18656699af76941b20b856661be4b9509262b2f14423b35e1521d7fdb3',historical_result_unchanged:true,not_replayed:true});
 for(const[arch,b]of Object.entries(report.normal_programme_builds)){assert.equal(b.arch,arch);assert(b.portable_build_artifacts_complete_and_verified&&b.all_original_build_gates_retained);assert.equal(b.source_inputs_sha256,report.frozen_inputs_sha256);assert.equal(b.source_overrides,0);assert(!b.signed&&!b.installed&&!b.all50_commercial);assert.equal(b.eager_javascript_budget,1200000);assert.equal(b.eager_javascript_bytes,1174533);assert.equal(b.new_static_contract_tests,4);}
 for(const k of['signed','normal_upgrade_accepted','Main19100_download_buttons_fixed','all50_commercial'])assert.equal(report[k],false,k);assert.equal(report.source_overrides,0);assert.equal(report.application_manifests_changed,0);
});
test('all50 signed application manifests and distribution credentials are unchanged',()=>{
 assert.equal(sha(read('dist/catalog-v1.json')),'247c8db6cc762413c0779f8cb8a251b16d01b641b109981f084076c20f104813');
 assert.equal(sha(read('signatures/catalog-v1.sig')),'4828f4a705f62ca1c8e2380528e0b1d65719e0be37c561790343862c60936727');
 assert.equal(sha(read('signatures/catalog-v1.bundle.json')),'deb1a606c402933f40b772c920de3396f2b6c8d6c910b581c4acef6b7f6b7f25');
 assert.equal(sha(read('signatures/catalog-v1.pub.pem')),'659ea4edcecaf23a586e2ff371616fde5f6ee7c219fb70fa978816e2b10acf75');
 const catalog=json('dist/catalog-v1.json');assert.equal(catalog.apps.length,50);for(const app of catalog.apps)assert.equal(sha(read('dist/apps/'+app.id+'/'+app.version+'/manifest.json')),app.sha256);
});
