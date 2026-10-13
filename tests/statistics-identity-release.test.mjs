import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {verifyCurrentSource,sha} from './current-source-authority.mjs';
const read=p=>readFile(new URL('../'+p,import.meta.url),'utf8');
const historical={
  "schema_version": "6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b",
  "reviewed_statistics_version_release": "3c441911afe82966f3dbe4bc56db6337914c15777b95e3e9796424489dbb6576",
  "reviewed_handler_release": "a48ff16efd3b5d0259658ff0e5fa00a6f9ff32db38d0e8f5110c95d6edad6428",
  "reviewed_lease_release": "7359f43424012ee32cfb929979394b7cb96f85bf45a8cfe23a78ca2acc63e8cf",
  "reviewed_canonical_release": "c61bc0648e4b8f82e369960e115e0eed26f37ff1d25c1b6c0a994b3fb8a45553",
  "reviewed_interlock_release": "3a5cbacfba7078f42e1a78d6171094354bbca173c961d002bb92d005e9c1b29e",
  "reviewed_fixture_input_release": "51cf2b2fcb39da466f41baa8f42edbc357519ffb9d7c39e3f87e84ecdf37e8df",
  "reviewed_quiescent_stop_release": "80284a2246d9664e377c466a0bc163d50c9eb38a440b06ed2623b409d5a0d247",
  "reviewed_startup_release": "3e708725b11f52424f28ff12deed5f82abdabf4f671f91d56cca6cfc79f5450a",
  "policy": "21875ff6f538aaf843e6753b00bc8eaa55912d9893a9f62105b6fd1c8bf56a75",
  "commercial_feature_parity_complete": "fcbcf165908dd18a9e49f7ff27810176db8e9f63b4352213741664245224f8aa",
  "reviewed_native_queue_release": "9dc5b618f5690a53c6a93abf980d9fbe52be696553969e2ae676b86c1263f816",
  "reviewed_release_retention_release": "890ca1ac9e07f3aa7abc93d06fb16fa82b305170fe6e9037c811f58e980e97b6",
  "reviewed_upgrade_transaction_release": "ae87d133201486775664bf69ce17868c5e788895157fe61975a852c66399d653",
  "previous_traffic_release": "6ed7a0e56e8325c693a015b0dcee667d009b77e6c943e99cad4d5ed8199ae40d",
  "previous_source_release": "a66564bdb7c235ec5d006d49e018a9c7f8a90146f0b062b6b15446ea30fa1555",
  "previous_gateway_release": "7e4005b1f7ddbf9df7fe64d5f1850d240990abfd89339acf48f44fe31c95dda2",
  "reviewed_normal_release": "af252b1e2362256018b10f939754ba6cc8269920518151ba7b33c434e9661d17",
  "previous_load_alert_release": "40db3233554961726e76d8e9eaaebaa34c133154a68377ba121549adc69aad8d",
  "previous_main_delivery": "aed044ba17280349ebf85c0b32f4508a4b8dfa0d9f9aa8d8fbd64debba114dd6",
  "catalog_delivery": "a184526f22afedebd6bd1a83f8fa376a1d3ba9e8cdb182bfdc103700a97798fe",
  "references": "b86b43474ea984a2c22e3dbf2ed7de4c5249daa498ac699e72ae901465583e94",
  "common_checks": "72d7d6db5deb284969def6f879f9820f998878161c935d67c4ed74a68de897a4"
};
test('old historical proof cohorts retain their own immutable source and evidence, not relabelled as new release',async()=>{
 const c=JSON.parse(await read('registry/functional-contracts.json'));
 for(const [key,pin]of Object.entries(historical))assert.equal(sha(JSON.stringify(c[key])),pin,key);
 assert.equal(c.reviewed_statistics_version_release.release,'0.1.0-dev.proapps24statsversionbelq');
 assert.equal(c.reviewed_statistics_version_release.frozen_inputs_sha256,'918458c33fde22e77952d50b9a976bf124321b4106c4e9ec366b67edf4be24d0');
});
test('exact new source authority binds strict statistics2.5 and versioned immutable guard migration',async()=>{
 const {c,r,i,f}=await verifyCurrentSource();
 const required=['internal/executor/app_statistics_schema_linux.go','internal/executor/app_statistics_schema_linux_test.go','internal/executor/app_statistics_lifecycle_linux.go','internal/executor/app_statistics_requests_linux.go','internal/executor/app_statistics_archives_linux.go','internal/executor/app_statistics_gzip_linux.go','internal/executor/app_statistics_log_transaction_linux.go','internal/executor/app_statistics_health_native_linux_test.go','scripts/test-statistics-history.mjs'];
 for(const p of required){assert.match(f.files[p],/^[a-f0-9]{64}$/);assert.equal(i.files[p],f.files[p]);}
 const app=JSON.parse(await read('dist/apps/website-statistics-v2/2.5.0/manifest.json'));assert.deepEqual(app.required_panel_features,['statistics-cursor-retirement-v1','statistics-request-identity-v1']);
 assert.equal(sha(await read('dist/apps/website-statistics-v2/2.5.0/manifest.json')),'7a2d358fbb5f5a3bf0718b72ccc7401ae83df4d10596da837d1ed259a2ce2d13');
 assert.equal(f.files['packaging/start-guard-install.py'],'95b7f0482ffc178866ac5f4ed7f054231919c6ccfd8abc4ba87ed162174b5494');
 const guard=await read('panel-integration/packaging/start-guard-install.py');
 for(const p of ["GUARD = '/usr/lib/panel-program-upgrade/start-guard-v3'","PREVIOUS = '/usr/lib/panel-program-upgrade/start-guard-v2'",'retained_guards(transaction)','startup-guard-v3-transition.json','immutable legacy guard changed during transition'])assert(guard.includes(p),p);
 for(const arch of ['arm64','amd64'])assert(guard.includes(c.reviewed_lease_release.signed_normal_release[arch].guard_program));
 assert.equal(r.actual_normal_development_upgrade.proof_sha256,'b812d31beeb82f0db0358e8b1f7c22941d5b51f0a7a092d1886b4710f0ecf851');
 assert.equal(r.actual_normal_development_cold_boot.proof_sha256,'c5195e4750ca11fd18d2b0d6c6c77ea3e505efc28e7f37e2e6213e22a09fc87a');
 assert.equal(r.actual_normal_development_cold_boot.loaded_fixed_guard_conditions,5);
 assert.equal(r.full_current_native_companion_verified,true);
 assert.equal(r.actual_normal_native_companion.proof_sha256,'068611dbe1d6e09610cf5df0d8f5e50ff8d077c7423bbc3d879015336b24459a');
 assert.deepEqual([r.actual_normal_native_companion.executor.pass,r.actual_normal_native_companion.executor.fail,r.actual_normal_native_companion.executor.skip],[701,0,126]);
 assert.deepEqual([r.actual_normal_native_companion.startup.pass,r.actual_normal_native_companion.startup.fail,r.actual_normal_native_companion.startup.skip],[10,0,1]);
 assert.equal(r.actual_normal_native_companion.only_runtime_condition_change,'panel-mysql-overwrite-recovery.service');
 assert.equal(r.actual_normal_native_companion.condition_static_argv_code_status_preserved,true);
 assert.equal(r.actual_normal_native_health.proof_sha256,'42430fe49f848d827ca966a15939d607cc3b094d78e0e697b0951e477e869743');
 assert.equal(r.actual_normal_native_health.normal_companion_sha256,r.signed_normal_release.arm64.companion);
 assert.deepEqual([r.actual_normal_native_health.pass,r.actual_normal_native_health.fail,r.actual_normal_native_health.skip],[1,0,0]);
 assert.equal(r.actual_normal_native_health.host_systemd_application_update_verified,false);
 for(const k of ['actual_signed_statistics_25_update_verified','production_layout_upgrade_verified','cold_boot_orphan_interlock_verified','main_release_delivered','main_changed','all_50_commercial'])assert.equal(r[k],false,k);
 assert.equal(c.commercial_feature_parity_complete,false);assert.equal(r.main_auto_installed_new_apps,0);
});
