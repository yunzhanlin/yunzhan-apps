import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {createHash} from 'node:crypto';
const root=fileURLToPath(new URL('../',import.meta.url)),scope='panel-integration-php-security/',read=n=>fs.readFileSync(path.join(root,n)),json=n=>JSON.parse(read(n)),sha=b=>createHash('sha256').update(b).digest('hex');
const added=['internal/appcatalog/php_security_features.go','internal/appcatalog/php_security_features_test.go','internal/core/php_security_admission_test.go','internal/executor/php_security_admission_linux_test.go','internal/runtimecatalog/php_security.go','internal/runtimecatalog/php_security_admission_test.go','internal/runtimecatalog/php_security_test.go','scripts/test-php-security.mjs','web/src/phpSecurity.ts'];
const changed=['internal/appcatalog/panel_features.go','internal/core/http.go','internal/core/runtime_bundles.go','internal/core/runtime_bundles_test.go','internal/core/runtime_worker_test.go','internal/core/runtimes.go','internal/executor/install_linux.go','internal/runtimecatalog/catalog.go','packaging/build-release.sh','web/src/App.vue'];
test('PHP security export is exact1761 normal-source files and1311 Go members without overlays or altered historical PHP identities',()=>{
 const i=json(scope+'source-sha256.json'),old=json('panel-integration-mobile-delivery/source-sha256.json'),bound=json(scope+'release-source-inputs.json');
 assert.equal(sha(read(scope+'source-sha256.json')),'9150b22af9befecceaf39e1366a6a3d42bebae29d0745d5d2d3ad3476506ebe2');assert.equal(i.release.frozen_inputs_sha256,'16c4e3158adc0a83376b72dbfb022b580283cb091d415e0bda97a258cceab579');assert.equal(i.release.archive_sha256,'de12fb3815bc5617502c2494e1f95db9d813e948e913c825e024477408e9d900');
 assert.deepEqual(bound.files,i.files);assert.deepEqual(i.test_overrides,{});assert.equal(Object.keys(i.files).length,1761);assert.equal(Object.keys(i.files).filter(n=>n.endsWith('.go')).length,1311);assert(Object.keys(old.files).every(n=>Object.hasOwn(i.files,n)));
 assert.deepEqual(Object.keys(i.files).filter(n=>!Object.hasOwn(old.files,n)).sort(),added);assert.deepEqual(Object.keys(i.files).filter(n=>Object.hasOwn(old.files,n)&&i.files[n]!==old.files[n]).sort(),changed);
 for(const[n,h]of Object.entries(i.files)){assert(path.posix.normalize(n)===n&&!path.isAbsolute(n)&&!n.split('/').some(p=>['..','.local','.git','node_modules'].includes(p)));const s=fs.lstatSync(path.join(root,scope,n));assert(s.isFile()&&!s.isSymbolicLink()&&s.nlink===1);assert.equal(sha(read(scope+n)),h,n);}
 assert.equal(i.files['web/src/FileManager.vue'],old.files['web/src/FileManager.vue']);
 const array=p=>read(p+'internal/runtimecatalog/catalog.go').toString().match(/var PHP = \[\]Release\{[\s\S]*?\n\}/)?.[0];assert(array(scope));assert.equal(array(scope),array('panel-integration-mobile-delivery/'));
});
test('original signed normal archives and genuine Linux287 models per architecture do not claim installed PHP or commercial acceptance',()=>{
 const r=json('registry/php-security-core.json'),i=json(scope+'source-sha256.json');assert.equal(r.frozen_inputs_sha256,i.release.frozen_inputs_sha256);assert.equal(r.source_overrides,0);assert.equal(r.exported_files,1761);
 assert(Object.values(r.recording_boundaries).every(v=>v===false));assert(!JSON.stringify(r).includes('/Volumes/')&&!JSON.stringify(r).includes('/var/lib/'));
 for(const arch of ['arm64','amd64']){const a=r.normal_archives[arch];assert(a.original_programme_key_signature_verified);assert.equal(a.root_native_model_tests,175);assert.equal(a.root_packaging_tests,112);assert.equal(a.skipped,0);assert.equal(a.actual_Linux_UID65534_feature_cases,66);assert(a.current_F28_original_signed50_accepted);for(const key of ['archive_sha256','manifest_sha256','signature_sha256','normal_build_log_sha256','root_native_proof_sha256','root_packaging_proof_sha256','feature_model_proof_sha256','current_F28_signed50_proof_sha256'])assert.match(a[key],/^[a-f0-9]{64}$/);assert(a.archive.includes(r.release));}
 assert(r.prepublication_models.original_ABI_driver_parser_failed_after_VM_success);assert.equal(r.prepublication_models.original_VM_runs_exit,0);assert.equal(r.prepublication_models.local_driver_original_exit,1);assert(r.prepublication_models.original_failures_and_raw_outputs_retained&&r.prepublication_models.no_test_or_installer_replay_to_relabel_original_driver);
});
test('new normal source pins all4 official source digests and keeps advisory status separate from a healthy binary',()=>{
 const r=json('registry/php-security-core.json'),code=read(scope+'internal/runtimecatalog/php_security.go').toString();
 assert.equal(r.advisory.source,'https://www.php.net/archive/2026.php');assert.deepEqual(r.advisory.identities,['CVE-2026-109618','CVE-2026-109619']);assert.deepEqual(Object.values(r.advisory.patched_versions),['8.2.35','8.3.36','8.4.27','8.5.12']);
 for(const h of ['9db4204f0a2d1911277ae832185e07bb4c3b3559772753a70d2968ca346d6910','c93f3441f87f6ab156bef4432db215d7e61ca2c0183bb3a2aa28d9886ab59f53','5bafed9994c1a49796b25b5f61c22c9183bfe046b6acc7b363842d03c77f972f','81a0f450349e84b08eb43faa85f8a4c835684f3cc1c50471775d1317a046c525'])assert(code.includes(h));
 for(const text of ['affected','fixed-for-advisory','unknown','RuntimeInstallAdmission','PHPReleaseChoices'])assert(code.includes(text),text);
 assert(r.source_authenticity.actual_detached_PGP_verification&&r.source_authenticity.corrupted_archive_and_cross_version_signature_refused);assert.equal(r.source_authenticity.verification_process_UID,65534);
});
test('security selectors and independent exact-package feature are part of the ordinary build rather than metadata-only application shells',()=>{
 const build=read(scope+'packaging/build-release.sh').toString(),features=read(scope+'internal/appcatalog/php_security_features.go').toString(),native=read(scope+'internal/executor/install_linux.go').toString(),ui=read(scope+'web/src/App.vue').toString();
 assert(build.includes('node --test scripts/test-php-security.mjs'));assert(features.includes('php-security-20261021-v1'));assert(features.includes('validatePHPSecurityRequirement'));assert(native.includes('runtimecatalog.RuntimeInstallAdmission(r)'));assert(native.includes('downloadRuntimeSource'));assert(ui.includes('phpSecurity'));
 for(const n of ['internal/runtimecatalog/php_security_admission_test.go','internal/core/php_security_admission_test.go','internal/executor/php_security_admission_linux_test.go','internal/appcatalog/php_security_features_test.go'])assert(Object.hasOwn(json(scope+'source-sha256.json').files,n));
 assert.equal(sha(read(scope+'scripts/web-entry-budget.mjs')),json('panel-integration-mobile-delivery/source-sha256.json').files['scripts/web-entry-budget.mjs']);
});
test('all23 original workflow jobs stay byte-exact before the separately compiled new PHP security gate',()=>{
 const workflow=read('.github/workflows/verify.yml'),marker='\n  php-security-native-amd64:\n',at=workflow.indexOf(marker);assert(at>0);assert.equal(sha(workflow.subarray(0,at)),'d4f4c1f77641e83d1895de4dad70b5844628a63b57fcbd59c1258bdb75964dc7');
 const gate=workflow.subarray(at).toString();for(const text of ['timeout-minutes: 45','panel-integration-php-security','test -p 1 ./... -count=1','go vet ./...','tools/run-php-security-ci.mjs','tools/check-php-security-schema.mjs','TestPublishedRepositoryCurrentSignedManifestABI','scripts/test-php-security.mjs','test_*.py','scripts/web-entry-budget.mjs'])assert(gate.includes(text),text);assert(!gate.includes('continue-on-error')&&!gate.includes('-overlay='));
 const runner=read('tools/run-php-security-ci.mjs').toString();assert(runner.includes("length,66)"));assert(runner.includes("RuntimeInstallShutdown)',41"));assert(runner.includes("Task|PHPSecurity)',134"));assert(runner.includes("names.filter(n=>gated.has(n)).length,9"));assert(!runner.includes('length,16)'));
});
