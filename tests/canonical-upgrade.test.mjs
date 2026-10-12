import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {createHash} from 'node:crypto';
const read=p=>readFile(new URL('../'+p,import.meta.url),'utf8'),sha=b=>createHash('sha256').update(b).digest('hex');

test('canonical privileged paths and scoped diagnostics bind the normal signed candidate without dismissing the earlier CI failure',async()=>{
 const c=JSON.parse(await read('registry/functional-contracts.json')),r=c.reviewed_canonical_release,old=c.reviewed_interlock_release,current=c[c.current_reviewed_release];
 const i=JSON.parse(await read('panel-integration/source-sha256.json')),f=JSON.parse(await read('panel-integration/release-source-inputs.json'));
 assert.equal(c.current_reviewed_release,'reviewed_statistics_version_release');assert.equal(r.release,'0.1.0-dev.proapps24canonicalbejp');assert.equal(current.frozen_inputs_sha256,f.frozen_inputs_sha256);assert.equal(current.signed_normal_release.amd64.archive,f.archive_sha256);
 assert.equal(Object.keys(i.files).length,1227);assert.equal(Object.keys(f.files).length,1186);assert.equal(Object.keys(i.test_overrides??{}).length,0);
 for(const p of r.only_frozen_input_changes){assert.equal(sha(await read('panel-integration/'+p)),f.files[p],p);assert.equal(i.files[p],f.files[p],p);}
 const helper=await read('panel-integration/packaging/upgrade-release.py');
 for(const s of ['def scoped_path(self, path):','not path.is_absolute()',"'..' in path.parts",'self.root not in path.parents','path = self.scoped_path(path)','target = self.scoped_path(target)'])assert(helper.includes(s),s);
 for(const arch of ['amd64','arm64'])for(const p of ['panel','executor','guard_program','development_helper','guard_installer','prune_helper'])assert.equal(r.signed_normal_release[arch][p],old.signed_normal_release[arch][p],arch+':'+p);
 assert.equal(current.signed_normal_release.arm64.upgrade_helper,sha(helper));assert.equal(r.normal_build_python_tests,115);assert.equal(r.normal_build_python_skips,41);assert.equal(r.normal_build_node_gates,36);
 const n=r.actual_normal_native_fixtures;assert.equal(n.passed,true);assert.equal(n.executor_pass,663);assert.equal(n.executor_fail,0);assert.equal(n.executor_skip,124);assert.equal(n.python_count,42);assert.equal(n.python_skips,0);assert.equal(n.startup_pass,9);assert.equal(n.startup_skip,1);assert.equal(n.installed_state_preserved,true);assert.equal(n.candidate_installed,false);
 const u=r.actual_old_version_production_upgrade;assert.equal(u.passed,true);assert.equal(u.installer_exit,0);assert.equal(u.actual_loaded_service_conditions_verified,5);assert.equal(u.original_sql_tables_compared,21);assert.equal(u.original_credentials_login_verified,true);assert.equal(u.original_schema_migrations_preserved,true);assert.equal(u.nginx_master_enablement_and_active_state_preserved,true);assert.deepEqual(u.changed_protected_fields,[]);
 assert.equal(u.proof_sha256,'ac927bfc303ceb8bb5357d1f1f54d96f24b6b8c3e435c00b2e0aa3a2f6159e30');assert.equal(u.actual_candidate_ready_readonly_maintenance_observations,15);
 const failure=r.retained_main_ci_failure;assert.equal(failure.run,38209943783);assert.equal(failure.conclusion,'failure');assert.equal(failure.resolved,false);
 const fixture=await read('panel-integration/internal/upgradeguard/startup_linux_test.go');for(const s of ['own-kernel-entries','parent-live-proof','parent-exact-lease','TestStartupRootLiveLeaseStaleBootPIDBytesAndUnprivilegedRead'])assert(fixture.includes(s),s);
 assert.equal(r.retained_pre_baseline_fixture_failure.passed,false);assert.equal(r.retained_pre_baseline_fixture_failure.proof_created,false);
 for(const p of ['normal_fresh_install_verified','older_main_original_development_retrofit_verified','current_native_failure_rollback_verified','cold_boot_orphan_interlock_verified','durable_interrupted_journal_recovery_complete','installer_death_during_constructor_verified','main_release_delivered','all_50_commercial'])assert.equal(r[p],false,p);
 assert.equal(c.commercial_feature_parity_complete,false);assert.equal(c.apps.length,50);assert.equal(r.main_auto_installed_new_apps,0);
});
