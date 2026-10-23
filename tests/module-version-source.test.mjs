import test from'node:test';import assert from'node:assert/strict';import fs from'node:fs';import path from'node:path';import{fileURLToPath}from'node:url';import{createHash}from'node:crypto';
const root=fileURLToPath(new URL('../',import.meta.url)),scope='panel-integration-module-version/',read=n=>fs.readFileSync(root+n),json=n=>JSON.parse(read(n)),sha=b=>createHash('sha256').update(b).digest('hex');
test('module version correction is an exclusive normal1796-file1343-Go frozen export,never overlays',()=>{
 const index=json(scope+'source-sha256.json');assert.equal(sha(read(scope+'source-sha256.json')),'37b5a6885fc685204ca8b15f2bc2d873013749a25987973d39bd8386dcbff491');
 assert.equal(index.release.frozen_inputs_sha256,"41c4295d400488bc6d69faa6a36a3a9556fc50b0b7e14d2011b083b964113cb4");assert.equal(index.release.archive_sha256,'0833fd8c7af09e2bd23f93a379fff96fffb034a230e20237d6a9cdcb4f9679a1');
 assert.equal(Object.keys(index.files).length,1796);assert.equal(Object.keys(index.files).filter(n=>n.endsWith('.go')).length,1343);assert.deepEqual(index.test_overrides,{});assert.deepEqual(json(scope+'release-source-inputs.json').files,index.files);
 for(const[n,h]of Object.entries(index.files)){assert.equal(path.posix.normalize(n),n);assert(!path.isAbsolute(n)&&!n.split('/').some(c=>['..','.git','.local','node_modules'].includes(c)));const s=fs.lstatSync(root+scope+n);assert(s.isFile()&&!s.isSymbolicLink()&&s.nlink===1);assert.equal(sha(read(scope+n)),h,n);}
 assert.equal(index.files['web/src/FileManager.vue'],'f4ae7a99782e0705d9e7cc34b2b6df130fee5fdf5546afc3cad4d9b1370f92bc');
});
test('historicalF36 remains immutable and only the exact independently reviewed native Apache and module-version paths differ',()=>{
 const now=json(scope+'source-sha256.json'),old=json('panel-integration-apache-noop/source-sha256.json'),changed=["dev/panel-apache-body-build@.service","internal/appcatalog/panel_features.go","internal/core/apache_waf.go","internal/core/app_registry.go","internal/core/software_apps.go","internal/core/waf_apply_requests.go","internal/core/worker.go","internal/executor/apache_body_site_edit_linux.go","internal/executor/apache_waf_health_linux.go","internal/executor/apache_waf_linux.go","internal/executor/apache_waf_remove_linux.go","internal/executor/app_module_record_linux.go","internal/executor/app_modules_linux.go","packaging/build-release.sh","scripts/test-apache-body-build.mjs","scripts/test-waf-configuration-version.mjs","web/src/ApacheBodyBuild.vue","web/src/WafWorkspace.vue","web/src/wafConfigurationVersion.ts"],added=["internal/appcatalog/apache_native_body_features.go","internal/appcatalog/apache_native_body_features_test.go","internal/core/apache_waf_version.go","internal/core/apache_waf_version_test.go","internal/core/software_install_version.go","internal/core/software_install_version_test.go","internal/executor/apache_body_site_noop_linux.go","internal/executor/apache_body_site_noop_linux_test.go","internal/executor/apache_waf_native_lifecycle_linux.go","internal/executor/apache_waf_native_lifecycle_linux_test.go","internal/executor/apache_waf_native_preview_linux.go","internal/executor/app_mobile_signed_version_linux_test.go","scripts/test-apache-body-policy.mjs","web/src/ApacheBodyPolicy.vue","web/src/apacheBodyPolicy.ts"];
 assert(Object.keys(old.files).every(n=>Object.hasOwn(now.files,n)));assert.deepEqual(Object.keys(now.files).filter(n=>!(n in old.files)).sort(),added);assert.deepEqual(Object.keys(old.files).filter(n=>old.files[n]!==now.files[n]).sort(),changed);
 for(const[n,h]of Object.entries(old.files))if(!changed.includes(n))assert.equal(now.files[n],h,n);
 for(const n of['internal/executor/program_upgrade_queues_linux.go','internal/executor/runtime_install_resources_linux.go','internal/runtimecatalog/catalog.go'])if(n in old.files)assert.equal(now.files[n],old.files[n],n);
 assert(read(scope+'internal/executor/program_upgrade_queues_linux.go').toString().includes('5*time.Second'));
});
test('every signed module carries its exact version and retained originals resolve read-only before dependencies or dispatch',()=>{
 const queue=read(scope+'internal/core/app_registry.go').toString(),worker=read(scope+'internal/core/worker.go').toString(),resolver=read(scope+'internal/core/software_install_version.go').toString(),sink=read(scope+'internal/executor/app_modules_linux.go').toString();
 assert(queue.includes('queueSoftwareActionBound(manifest.Delivery.Target, "install", in.Settings, manifest.Version, key, u.Username, bind)'));
 assert(worker.indexOf('softwareInstallExecutionVersion(s.DB, j, payload.Version)')<worker.indexOf('waitAppDependencies(dependencyCtx, e, j.TargetID)'));
 for(const x of['job_payload_sha256','request_sha256','runtime_job_id','requested != version','softwareRegistryAppID(j.TargetID)','ensureRegistryRequestOpen(q, key)','readUserAccess(q, actor)','app_registry_update_requests'])assert(resolver.includes(x),x);
 assert(!resolver.includes('.Exec(')&&!resolver.includes('.ExecContext(')&&!resolver.includes('INSERT INTO')&&!resolver.includes('DELETE FROM'));
 assert(sink.includes('selectedVersion = "1.3.0"'));assert(sink.includes('core.ValidateSoftwareInstallVersion(id, selectedVersion)'));assert(sink.includes('installedRecord = previous'));assert(sink.includes('id == "mobile-pwa") && action == "install" && s.moduleInstalled(id)'));
});
test('real authenticated signed package integration exercises the private Unix sink,store update and unchanged original payload',()=>{
 const real=read(scope+'internal/executor/app_mobile_signed_version_linux_test.go').toString(),unit=read(scope+'internal/core/software_install_version_test.go').toString();
 for(const x of['ed25519.GenerateKey','ed25519.Sign(private','net.Listen("unix", socket)','core.NewServer','core.RunWorker','/api/bootstrap','/api/login','/api/app-registry/mobile/install','/api/app-registry/mobile/update','registry(true)','row.UpdateAvailable','retainedPayload != originalPayload','wait(duplicate, "failed")','20*time.Second'])assert(real.includes(x),x);
 assert(!real.includes('t.Skip('));
 for(const x of['SoftwareAppCatalog()','"queued", "failed", "needs_attention", "succeeded"','originalSignedVersionBytes','unbound-native','different-kind','noop','revoked'])assert(unit.includes(x),x);
 assert(!unit.includes('t.Skip('));
});
test('new28th native gate preserves every byte of original27 jobs and requires no-skip exact integration counts',()=>{
 const raw=read('.github/workflows/verify.yml'),at=raw.indexOf('\n  module-version-native-amd64:\n');assert(at>0);assert.equal(sha(raw.subarray(0,at)),"3414b7c87adb612993b6b2073cbff540784ab501f94de4662bca5283c99b4b23");
 const gate=raw.subarray(at).toString();for(const x of['panel-integration-module-version','prepare-module-version-apache-ci.py','run-module-version-native-ci.mjs','--race','go vet ./...','TestPublishedRepositoryCurrentSignedManifestABI'])assert(gate.includes(x),x);
 for(const x of['continue-on-error','-overlay=','reset-failed','killall','pkill'])assert(!gate.includes(x),x);
 const runner=read('tools/run-module-version-native-ci.mjs').toString();for(const x of['expectedPasses:78','expectedPasses:93',"e.Action==='skip'",'private_integration_not_host_app_installation:true','all50_commercial:false'])assert(runner.includes(x),x);
});
test('native prerequisite is a genuine exact pinned Apache build,never a fabricated executable or existing runtime replacement',()=>{
 const p=read('tools/prepare-module-version-apache-ci.py').toString();
 for(const x of['ed9a9d4500fb48bb28eaffb3ba71d06ccf86d498fa13ab9f781da010cc488498','read_source(\'internal/executor/install_linux.go\')','assert len(blocks)==1','not os.path.lexists(prefix)','--property=User=panel-ci-apache','--property=MemoryMax=768M','--property=MemorySwapMax=0',"['/usr/bin/make','-j1']",'Server version: Apache/2.4.68 (Unix)',"'service_started':False"])assert(p.includes(x),x);
 assert(p.includes('os.umask(0o022)')&&p.includes('existing_parent_NOT_repaired'));
 assert(!p.includes('shutil.rmtree')&&!p.includes('cp /bin/true')&&!p.includes('touch('));
 const runner=read('tools/run-module-version-native-ci.mjs').toString();assert(runner.includes('fs.writeSync(1,z.stdout'));assert(runner.indexOf("stem+'.process.json'")<runner.indexOf('assert.equal(z.status,0)'));
});
