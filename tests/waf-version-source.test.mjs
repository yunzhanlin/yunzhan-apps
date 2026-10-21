import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {createHash} from 'node:crypto';
import {preNginxRuntimeRead} from './pre-nginx-runtime-release.mjs';
const root=fileURLToPath(new URL('..',import.meta.url)),read=n=>preNginxRuntimeRead(n,fs.readFileSync(path.join(root,n))),json=n=>JSON.parse(read(n)),sha=b=>createHash('sha256').update(b).digest('hex');
const scope='panel-integration-waf-version/',prior='panel-integration-waf-health/';
test('version-bound WAF and new legacy-template source is exactly the immutable signed release',()=>{
 const r=json('registry/waf-version-core.json'),a=json(prior+'source-sha256.json'),b=json(scope+'source-sha256.json');
 assert.equal(r.version,'0.1.0-dev.proapps24wafversionbipv');assert.equal(r.frozen_inputs_sha256,'ed18e662e887605482462ee64d11d448b0de692f81e022044cd1f097dc526dcf');
 assert.equal(r.prior_frozen_inputs_sha256,a.release.frozen_inputs_sha256);assert.equal(b.release.frozen_inputs_sha256,r.frozen_inputs_sha256);
 assert.equal(r.frozen_files,17413);assert.equal(r.exported_files,1710);assert.equal(Object.keys(b.files).length,1710);assert.equal(r.source_overrides,0);assert.deepEqual(b.test_overrides,{});
 assert.deepEqual(Object.keys(b.files).filter(n=>!Object.hasOwn(a.files,n)).sort(),r.added_from_prior);assert.equal(r.added_from_prior.length,8);
 assert.deepEqual(Object.keys(b.files).filter(n=>Object.hasOwn(a.files,n)&&b.files[n]!==a.files[n]).sort(),r.changed_from_prior);assert.equal(r.changed_from_prior.length,12);assert(Object.keys(a.files).every(n=>Object.hasOwn(b.files,n)));
 for(const [n,pin]of Object.entries(b.files))assert.equal(sha(read(scope+n)),pin,n);
 assert.equal(b.release.archive_sha256,r.normal_archives.amd64.archive_sha256);assert.equal(b.files['web/src/FileManager.vue'],'f4ae7a99782e0705d9e7cc34b2b6df130fee5fdf5546afc3cad4d9b1370f92bc');
 for(const n of ['internal/executor/program_upgrade_queues_linux.go','packaging/upgrade-release.py','packaging/development-upgrade.py','internal/core/waf_policy.go','internal/executor/waf_render.go'])assert.equal(b.files[n],a.files[n],n);
 assert.equal(r.country_activation_included,false);assert.equal(r.database_migration_added,false);assert.equal(r.application_manifests_changed,0);assert.equal(r.commercial_all50,false);assert.equal(r.Main19100_program_deployed_at_recording,false);
});
test('original history is not rewritten and model/container evidence is not signed-store installation',()=>{
 const r=json('registry/waf-version-core.json');
 for(const arch of ['arm64','amd64']){const a=r.normal_archives[arch];for(const k of ['archive_sha256','manifest_sha256','signature_sha256','normal_build_log_sha256'])assert.match(a[k],/^[a-f0-9]{64}$/);assert.equal(a.original_key_signature_verified,true);assert.equal(a.Core_signed_install_contract.temporary_fixture_key_only,true);assert.equal(a.Core_signed_install_contract.actual_original_key_app_installation,false);}
 for(const arch of ['arm64','amd64']){const u=r.normal_archives[arch].upgrade;assert.equal(u.ok,true);assert.deepEqual(u.actions,[{action:'preflight',exit:0},{action:'install',exit:0}]);for(const key of ['all102_schema_and_business_preserved','all15_kernel_values_preserved','complete_NFT_policy_handles_objects_preserved','SSH_Fail2ban_journald_lifetimes_and_configs_preserved','complete_statistics_history_and_cursors_preserved'])assert.equal(u[key],true,key);assert.equal(u.application_operations,0);}
 assert(r.original_AMD_readonly_refusals.every(x=>x.ok===false&&x.installer_dispatched===false));assert.equal(r.original_AMD_readonly_refusals.length,2);
 assert(r.actual_ARM_UI.visible_mismatch_warning&&r.actual_ARM_UI.preview_and_save_disabled);assert.equal(r.actual_ARM_UI.application_mutations,0);
 const l=r.legacy_PHP_boundary;assert.equal(l.functional_real_images,12);assert.equal(l.original_strict_NFT_receipts_still_false,true);for(const k of ['old_projects_rewritten','real_image_test_is_store_installation','legacy_runtime_security_support','existing_project_migration_accepted'])assert.equal(l[k],false,k);
});
test('ten original gates retain their tests with explicit historical WAF package serialization',()=>{
 const raw=read('.github/workflows/verify.yml'),at=raw.indexOf(Buffer.from('\n  waf-version-native-amd64:\n'));assert(at>0);assert.equal(sha(raw.subarray(0,at)),'8698a70f9401b3727fef3b3e0e2645bc0cb7b4bda687dc6a37aa595d84a9ec6a');
 const gate=raw.subarray(at).toString();for(const part of ['panel-integration-waf-version','sudo "$(command -v go)" test -p 1 ./... -count=1','go vet ./...','test -race','timeout 240s sudo python3','test-waf-configuration-version.mjs','TestWAFBoundHealthNativeTraffic','TestIsolatedLegacyPHPHiddenRoutingNativeTraffic','proapps24wafversionbipv'])assert(gate.includes(part),part);
 assert(!gate.includes('continue-on-error'));assert(!gate.includes('-overlay='));assert(!gate.includes('TestIsolatedLegacyPHPActualContainers'));
});
