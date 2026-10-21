import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {createHash} from 'node:crypto';
import {originalWAFHealthWorkflow,beforeWAFHealth} from './pre-waf-health-release.mjs';
import {preNginxRuntimeRead} from './pre-nginx-runtime-release.mjs';
const root=fileURLToPath(new URL('..',import.meta.url)),read=n=>preNginxRuntimeRead(n,fs.readFileSync(path.join(root,n))),json=n=>JSON.parse(read(n)),sha=b=>createHash('sha256').update(b).digest('hex');
const scope='panel-integration-waf-health/',prior='panel-integration-intrusion-admission/';
const added=['internal/appcatalog/waf_health_features_test.go','internal/executor/program_queue_actual_capture_linux_test.go','internal/executor/program_queue_refusal.go','internal/executor/program_queue_refusal_linux_test.go','internal/executor/program_queue_refusal_test.go','internal/executor/waf_health_binding_test.go','internal/executor/waf_health_native_linux_test.go','internal/executor/waf_health_upgrade_linux_test.go','scripts/test-waf-health-version.mjs'];
const changed=['cmd/executor/main.go','internal/appcatalog/panel_features.go','internal/core/waf_policy.go','internal/executor/program_upgrade_queues_linux.go','internal/executor/waf_render.go','internal/executor/waf_upgrade_linux.go','internal/executor/waf_versions.go','internal/executor/waf_versions_test.go','packaging/build-release.sh','packaging/development-upgrade.py','packaging/test_development_upgrade_safety.py','packaging/test_production_upgrade.py','packaging/test_program_queue_diagnostics.py','packaging/upgrade-release.py','web/src/WafWorkspace.vue'];
test('exact new normal signed source is immutable and has no overrides, country activation or schema changes',()=>{
 const r=json('registry/waf-health-core.json'),a=json(prior+'source-sha256.json'),b=json(scope+'source-sha256.json');
 assert.equal(r.version,'0.1.0-dev.proapps24periodicadmissionbimg');assert.equal(r.frozen_inputs_sha256,'1229eb75c583d7c3cfc9380f5e0030a8b5da14650e37188c4db51be23f5a4640');
 assert.equal(a.release.frozen_inputs_sha256,r.prior_frozen_inputs_sha256);assert.equal(b.release.frozen_inputs_sha256,r.frozen_inputs_sha256);assert.equal(r.frozen_files,17405);assert.equal(r.exported_files,1702);assert.equal(r.source_overrides,0);assert.deepEqual(b.test_overrides,{});assert.equal(Object.keys(b.files).length,1702);
 assert.deepEqual(Object.keys(b.files).filter(n=>!Object.hasOwn(a.files,n)).sort(),added);assert.deepEqual(Object.keys(b.files).filter(n=>Object.hasOwn(a.files,n)&&b.files[n]!==a.files[n]).sort(),changed);assert.deepEqual(Object.keys(a.files).filter(n=>!Object.hasOwn(b.files,n)),[]);
 assert.deepEqual(r.added_from_prior,added);assert.deepEqual(r.changed_from_prior,changed);for(const[n,pin]of Object.entries(b.files))assert.equal(sha(read(scope+n)),pin,n);
 assert.equal(b.release.archive_sha256,r.normal_archives.amd64.archive_sha256);assert.equal(r.country_activation_included,false);assert.equal(r.database_migration_added,false);assert.equal(r.commercial_all50,false);
 assert.equal(b.files['web/src/FileManager.vue'],'f4ae7a99782e0705d9e7cc34b2b6df130fee5fdf5546afc3cad4d9b1370f92bc');
});
test('only the signed WAF manifest changes; older handler remains unable to borrow new capabilities',()=>{
 const old=json(beforeWAFHealth+'catalog-v1.json'),current=json('dist/catalog-v1.json');assert.equal(old.apps.length,50);assert.equal(current.apps.length,50);
 const previous=new Map(old.apps.map(a=>[a.id,a]));for(const app of current.apps){assert(previous.has(app.id));if(app.id!=='nginx-waf')assert.deepEqual(app,previous.get(app.id),app.id);}
 const m=json('dist/apps/nginx-waf/2.5.2/manifest.json'),r=json('registry/waf-health-core.json');assert.equal(m.version,'2.5.2');assert.deepEqual(m.required_panel_features,['waf-bound-health-v1']);assert.equal(sha(read('dist/apps/nginx-waf/2.5.2/manifest.json')),r.app_manifest_sha256);
 assert.deepEqual(m.delivery,{provider:'panel-module',target:'nginx-waf',manage_route:'security'});assert.equal(r.app_version,'2.5.2');assert.equal(r.feature,'waf-bound-health-v1');
 assert.equal(r.signed_WAF_app_installed_acceptance_at_recording,false);assert.equal(r.Main19100_program_deployed_at_recording,false);
});
test('timer fix retains complete queue rejection and durable startup/recovery ordering, without retry or service reset',()=>{
 const source=read(scope+'packaging/upgrade-release.py').toString(),run=source.slice(source.indexOf('    def run(self):'),source.indexOf('    def rollback(self):'));
 const second=run.indexOf('        self.preflight()',run.indexOf('        self.preflight()')+1),lock=run.indexOf("self.lock(self.path('/var/lib/panel-executor/runtime-lifecycle.lock'))");assert(second>0&&second<lock);
 const sequence=['self.retain_candidate_plan()','self.defer_timer()',"self.journal('prepared')",'self.start_guard(install=True)','self.stop_timer()','self.queue_check()','self.native_prerequisites(create=True)','shutil.copytree(self.release, stage)','self.create_pending()','self.stop_writers()'];let cursor=-1;for(const item of sequence){const next=run.indexOf(item,cursor+1);assert(next>cursor,item);cursor=next;}
 assert.equal(run.split('self.queue_check()').length-1,4);assert(!run.includes('reset-failed'));assert(!run.includes("'stop', 'panel-mysql-overwrite-recovery.service'"));
 const reader=read(scope+'internal/executor/program_upgrade_queues_linux.go').toString();assert(reader.includes('5*time.Second'));assert(reader.includes('native program operation is queued; upgrade refused'));assert(reader.includes('native program operation is active, failed or transitional; upgrade refused'));
 const dto=read(scope+'internal/executor/program_queue_refusal.go').toString();assert(dto.includes('func (e *programQueueNativeRefusal) Error() string { return e.message }'));assert(dto.includes('len(raw) > 1024'));assert(!dto.includes('os/exec'));assert(!dto.includes('time.Sleep'));
 for(const contract of ['def original_periodic_recovery_can_be_observed_again(error):','def preflight_admission_is_readonly(self):','for attempt in range(3):','not self.preflight_admission_is_readonly()','time.sleep(0.25)',"value['unit'] != 'panel-mysql-overwrite-recovery.service'","value['job_type'] == 'start'",'named.st_dev, named.st_ino','held.st_dev, held.st_ino'])assert(source.includes(contract),contract);
 const cases=read(scope+'packaging/test_production_upgrade.py').toString();for(const name of ['full_second_preflight_does_not_hold_the_lease_needed_by_periodic_recovery','timer_suspension_is_durable_and_precedes_preparation_with_full_queues_still_checked','busy_original_queue_after_early_timer_suspension_is_not_retried_or_bypassed','sigkill_in_new_early_timer_gap_restores_only_owned_timer_without_program_or_database_replay'])assert(cases.includes('def test_'+name+'('));
});
test('native receipts distinguish actual isolated HTTP, filesystem models and normal signed upgrades',()=>{
 const r=json('registry/waf-health-core.json');for(const arch of ['arm64','amd64']){const a=r.normal_archives[arch],u=a.upgrade,n=a.actual_isolated_HTTP,q=a.native_queue_models;
  for(const k of ['archive_sha256','manifest_sha256','signature_sha256','normal_build_log_sha256'])assert.match(a[k],/^[a-f0-9]{64}$/);assert(a.original_key_signature_verified);assert.equal(n.requests,6);assert(n.old_2_5_1_bypass_reproduced&&n.new_2_5_2_binding_verified);assert.equal(n.installed_app_acceptance,false);assert.equal(q.top_level,24);assert.equal(q.skipped,0);
  assert.deepEqual(u.actions,[{action:'preflight',exit:0},{action:'install',exit:0}]);assert.equal(u.application_operations,0);for(const k of ['all102_schema_and_business_preserved','all15_kernel_values_preserved','complete_NFT_policy_handles_objects_preserved','SSH_Fail2ban_journald_lifetimes_and_configs_preserved','complete_statistics_history_and_cursors_preserved','original_failed_requests_not_replayed'])assert.equal(u[k],true,k);assert.match(u.proof_sha256,/^[a-f0-9]{64}$/);
 }
 assert.equal(r.Root_packaging_models.arm64.passed,224);assert.equal(r.Root_packaging_models.amd64.critical_passed,91);assert.equal(r.Root_packaging_models.amd64.aggregate214_240_second_timeout_retained,true);
 assert.deepEqual(r.original_AMD_failed_health_upgrades.map(v=>v.proof_sha256),['d61b8f8829177e1f80c2d651d769447725945735df0d6ff3f5867f194e460011','a5621168a300c2b5789ed24958738b9b24cafb72dc6309a1692ae8664ce9bbde','97edb2f9d6e615e710def82b8a2ddb123d2a3d8bf8c1e4b531326016417607be']);assert(r.original_AMD_failed_health_upgrades.every(v=>v.ok===false&&v.replayed===false));
});
test('historical nine-job workflow is preserved and new native gate exercises full original budgets',()=>{
 const raw=originalWAFHealthWorkflow(read('.github/workflows/verify.yml')),at=raw.indexOf(Buffer.from('\n  waf-health-native-amd64:\n'));assert(at>0);assert.equal(sha(raw.subarray(0,at)),'69b215c701922af629899e66df38b599d74fe0699a10b2b5b6f4f2fdffc1c33d');
 const gate=raw.subarray(at).toString();for(const item of ['sudo "$(command -v go)" test -p 1 ./... -count=1','go vet ./...','test -race','timeout 240s sudo python3','verify-waf-health-handler-boundary.mjs','TestWAFBoundHealthNativeTraffic','-timeout=80s','proapps24periodicadmissionbimg'])assert(gate.includes(item),item);assert(!gate.includes('continue-on-error'));assert(!gate.includes('-overlay='));
});
