import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {createHash} from 'node:crypto';
const root=fileURLToPath(new URL('../',import.meta.url));
const read=p=>fs.readFileSync(path.join(root,p));
const json=p=>JSON.parse(read(p));
const sha=b=>createHash('sha256').update(b).digest('hex');
const r=json('registry/statistics-stop-core-release.json'),scope='panel-integration-statistics-stop/';
test('current normal-release source export is exact, closed and independent of historical scopes',()=>{
 const index=json(scope+'source-sha256.json'),release=json(scope+'release-source-inputs.json');
 assert.equal(r.version,'0.1.0-dev.proapps24statstopbgwr');assert.equal(r.frozen_inputs_sha256,'73d37ae9b8ddecbb02d9d2c1adf1995b997ac60d25f32b4f43f551caefada078');
 assert.equal(r.frozen_files,17168);assert.equal(r.exported_files,1525);assert.equal(r.source_overrides,0);assert.deepEqual(index.test_overrides,{});assert.equal(Object.keys(index.files).length,1525);assert.deepEqual(index.files,release.files);
 assert.equal(index.release.frozen_inputs_sha256,r.frozen_inputs_sha256);assert.equal(index.release.archive_sha256,r.normal_original_key_archives.amd64.archive_sha256);
 assert.equal(release.archive,'panel-'+r.version+'-linux-amd64.tar.gz');
 for(const[p,digest]of Object.entries(index.files)){assert(!p.split('/').some(x=>['.local','.git','node_modules','..'].includes(x)));assert.equal(sha(read(scope+p)),digest,p);}
 const original=json('panel-integration-apache-sites/source-sha256.json');assert.equal(Object.keys(original.files).length,1517);assert.equal(original.release.frozen_inputs_sha256,'86f0c4792f7e0b81955d568179147dfe746949d0aaa06f2dea976b842663e8b2');
 const changed=Object.keys(index.files).filter(p=>index.files[p]!==original.files[p]);assert.equal(changed.length,20);assert(Object.keys(original.files).every(p=>index.files[p]));
 assert(changed.includes('packaging/test_statistics_stop_barrier.py')&&changed.includes('internal/executor/app_statistics_recovery_linux.go')&&changed.includes('cmd/executor/shutdown.go'));
 for(const p of ['internal/executor/apache_sites_linux.go','internal/executor/apache_waf_site_edit_linux.go','internal/executor/apache_waf_site_edit_linux_test.go','web/src/DockerManager.vue'])assert.equal(index.files[p],original.files[p]);
});
test('native fixture coverage does not relabel timed-out aggregate or original failed installed cases',()=>{
 const n=r.native_source_fixtures;assert.equal(n.go_functional_each_arch,33);assert.equal(n.arm64_root_packaging_passed,208);assert(n.arm64_whole_case_passed);assert.equal(n.amd64_root_packaging_unique_complete_passed,208);assert.equal(n.amd64_prior_complete_process_union_passed,202);assert.equal(n.amd64_new_missing_tests_passed,6);assert.equal(n.source_or_test_overrides,0);assert(n.original_240_second_aggregate_cases_still_failed&&n.all_original_test_assertions_and_240_second_controller_limit_retained);
 const m=r.actual_AMD_explicit_maintenance;assert(m.original_failed_upgrade_still_false&&m.original_hot_database_journal_and_installed_record_immutably_backed_up&&m.native_SQLite_rollback_only&&m.original_pre_upgrade_committed_history_preserved&&m.no_installer_service_stop_restart_or_program_replacement);assert.equal(m.core_business_projections_preserved,101);assert.equal(m.handler_source_inputs_sha256,'ac2bbaa38c83c9239977ae2571a61dc99286e528c953802939b52e01c89cb9ca');assert.equal(m.original_failed_upgrade_proof_sha256,'aa0f5ced302d3901fc6260cdd7d9e3b2becd0c29308c338e5f7a990336c06288');
 assert.equal(r.installed_Docker_business_acceptance,false);assert.equal(r.PHP_and_IDS_accepted_background_queues_fully_drained,false);assert.equal(r.commercial_all50,false);
});
test('both original-key QA upgrades and Main delivery retain explicit data and application boundaries',()=>{
 for(const arch of ['arm64','amd64']){const a=r.normal_original_key_archives[arch],q=r.actual_QA_normal_signed_upgrades[arch];for(const k of ['archive_sha256','manifest_sha256','signature_sha256','complete_normal_build_log_sha256'])assert.match(a[k],/^[a-f0-9]{64}$/);assert(a.signature_verified);assert.equal(q.preflight_exit,0);assert.equal(q.install_exit,0);assert.equal(q.original_business_projections_preserved,101);assert.equal(q.installed_app_records_preserved,20);assert(q.original_history_and_streams_preserved&&q.fresh_healthy_statistics_worker&&q.no_live_history_recovery_invoked&&q.nginx_process_not_restarted&&q.original_failed_upgrade_still_false);assert.match(q.proof_sha256,/^[a-f0-9]{64}$/);}
 const m=r.Main19100_normal_signed_development_upgrade;assert.equal(m.preflight_exit,0);assert.equal(m.install_exit,0);assert.equal(m.original_sites_preserved,58);assert.equal(m.original_installed_apps_preserved,4);assert.equal(m.analytics_version_preserved,'2.3.1');assert.equal(m.protected_non_program_entries_preserved,43013);assert(m.original_101_schema_migration_rows_and_business_projections_unchanged&&m.nginx_process_not_restarted&&m.ready_HTTP200&&m.website19101_HTTP200&&m.website_probe_after_exact_preservation&&m.no_app_operations);
 assert.equal(r.original_signer_sha256,'fe128e82b4e11345b320cd782134768bfe1a4df14947c425d7494873a7a7b7b5');assert.equal(r.original_public_key_sha256,'4ccfcc861d56a41e3ba7f7ace7e2432c815f366c58448d783df92c6632f01339');
});
test('new native AMD64 CI job appends without removing or weakening one byte of previous gates',()=>{
 const workflow=read('.github/workflows/verify.yml').toString(),at=workflow.indexOf('\n  statistics-stop-native-amd64:\n');assert(at>0);assert.equal(sha(Buffer.from(workflow.slice(0,at))),r.previous_workflow_full_prefix_sha256);assert.equal(r.previous_workflow_full_prefix_sha256,'14e8e68972be5c21357bb714ffd1f277f2417b7115824bbc8fe06f65cf96f45e');assert.doesNotMatch(workflow,/continue-on-error/);
 for(const value of ['runs-on: ubuntu-24.04',"timeout 240s sudo python3 -B -m unittest discover -s packaging -p 'test_*.py' -v",'test -p 1 ./... -count=1','go vet ./...',"-race ./internal/executor -run '^Test(StatisticsRecovery|ModuleWorker|WorkerLifecycle)'",'-race ./cmd/executor',"npm ci --prefix panel-integration-statistics-stop/web --ignore-scripts",'scripts/test-docker-scope.mjs','scripts/test-docker-site-binding.mjs','scripts/web-entry-budget.mjs'])assert(workflow.slice(at).includes(value),value);
});
