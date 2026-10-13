import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {createHash} from 'node:crypto';
const read=p=>readFile(new URL('../'+p,import.meta.url),'utf8'),sha=b=>createHash('sha256').update(b).digest('hex');

test('normal signed bounded lease scans and recorded immutable v2 transition preserve old failures and do not claim all50',async()=>{
 const c=JSON.parse(await read('registry/functional-contracts.json')),r=c.reviewed_lease_release,old=c.reviewed_canonical_release,current=c[c.current_reviewed_release];
 const i=JSON.parse(await read('panel-integration/source-sha256.json')),f=JSON.parse(await read('panel-integration/release-source-inputs.json'));
 assert.equal(c.current_reviewed_release,'reviewed_statistics_identity_release');assert.equal(r.release,'0.1.0-dev.proapps24leasebejz');
 assert.equal(r.frozen_source_files,16872);assert.equal(r.frozen_inputs_sha256,'c9a2b2cdbc39ff86d1fe3a27d86ada9587921898d638e8231b23145987b8004c');
 assert.equal(f.frozen_inputs_sha256,current.frozen_inputs_sha256);assert.equal(f.archive_sha256,current.signed_normal_release.amd64.archive);
 assert.equal(Object.keys(i.files).length,1250);assert.equal(Object.keys(f.files).length,1209);assert.equal(Object.keys(i.test_overrides??{}).length,0);assert.equal(r.source_overrides,0);
 assert.deepEqual(r.only_frozen_input_changes,['internal/upgradeguard/startup_linux.go','internal/upgradeguard/startup_lease_linux_test.go','packaging/start-guard-install.py','packaging/test_start_guard_install.py','packaging/test_production_upgrade.py']);
 for(const p of r.only_frozen_input_changes){const h=sha(await read('panel-integration/'+p));assert.equal(i.files[p],h,p);assert.equal(f.files[p],h,p);}
 const source=await read('panel-integration/internal/upgradeguard/startup_linux.go');
 for(const s of ['func startupLeaseSnapshot(','now().Add(100 * time.Millisecond)','attempt < 8','len(raw) > 4*1024*1024','!now().Before(deadline)','if ownsStartupLock(raw, record)','return err','matches == 1','return procRead("/proc/locks", 4*1024*1024)','}, time.Now)'])assert(source.includes(s),s);
 assert.equal((source.match(/ownerLive\(record, lock\)/g)||[]).length,2);
 assert.deepEqual(r.kernel_lock_enumeration.primary_sources,['https://raw.githubusercontent.com/torvalds/linux/master/fs/locks.c','https://raw.githubusercontent.com/torvalds/linux/master/fs/seq_file.c']);
 assert.equal(r.kernel_lock_enumeration.duplicates_accepted,false);assert.equal(r.kernel_lock_enumeration.max_fresh_scans,8);assert.equal(r.kernel_lock_enumeration.deadline_ms,100);
 const fixture=await read('panel-integration/internal/upgradeguard/startup_lease_linux_test.go');
 for(const s of ['calls != 3','calls != 8','calls != 1','absent, duplicate, foreign or shared kernel lease accepted','kernel I/O failure must refuse immediately','oversized enumeration accepted','late exact enumeration accepted'])assert(fixture.includes(s),s);
 const install=await read('panel-integration/packaging/start-guard-install.py');
 for(const s of ["GUARD = '/usr/lib/panel-program-upgrade/start-guard-v3'","LEGACY = '/usr/lib/panel-program-upgrade/start-guard-v1'","'startup-guard-v3-transition.json'","'legacy_retained':True","'previous_identity'","'candidate_sha256'","identity(actual[1]) != identity(original[1])","identity(actual_legacy[1]) != identity(info_before)",'unreviewed immutable previous guard','previous guard transition requires private authority and retained verified binaries','retained v3 transition evidence must not be overwritten'])assert(install.includes(s),s);
 assert(install.indexOf('transaction.atomic(proof,')<install.indexOf('transaction.atomic(target,'));
 for(const arch of ['amd64','arm64']){
  assert.equal(r.approved_legacy_guard_sha256[arch],old.signed_normal_release[arch].guard_program);
  assert(install.includes(r.approved_legacy_guard_sha256[arch]));assert.notEqual(r.signed_normal_release[arch].guard_program,r.approved_legacy_guard_sha256[arch]);
  assert.equal(current.signed_normal_release[arch].guard_installer,sha(install));
  for(const p of ['development_helper','upgrade_helper','prune_helper'])assert.equal(r.signed_normal_release[arch][p],old.signed_normal_release[arch][p]);
 }
 const python=await read('panel-integration/packaging/test_start_guard_install.py');
 for(const s of ['test_reviewed_legacy_transition_keeps_binary_and_records_scope_before_first_mutation','test_unknown_legacy_or_missing_private_authority_never_writes_v2','test_legacy_drift_and_transition_evidence_write_failure_do_not_replace_any_condition'])assert(python.includes(s),s);
 const n=r.actual_normal_native_fixtures;assert.equal(n.passed,true);assert.equal(n.executor_pass,663);assert.equal(n.executor_fail,0);assert.equal(n.executor_skip,124);assert.equal(n.python_count,45);assert.equal(n.python_skips,0);assert.equal(n.startup_pass,10);assert.equal(n.startup_skip,1);assert.equal(n.candidate_installed,false);
 assert.equal(n.normal_startup_companion_sha256,r.signed_normal_release.arm64.startup_companion);assert.equal(n.normal_archive_sha256,r.signed_normal_release.arm64.archive);
 const churn=r.actual_normal_native_churn;assert.equal(churn.passed,true);assert.equal(churn.pass,1000);assert.equal(churn.fail,0);assert.deepEqual(churn.churn_errors,[]);assert.equal(churn.original_state_preserved,true);assert.equal(churn.original_sql_tables_compared,21);assert.equal(churn.normal_companion_sha256,r.signed_normal_release.arm64.startup_companion);assert.equal(churn.proof_sha256,'201d5032c4878140158dada2da0af3821ca623dac92a13ecc877f18c80de6c83');
 const u=r.actual_reviewed_v1_to_v2_upgrade;assert.equal(u.passed,true);assert.equal(u.installer_exit,0);assert.equal(u.actual_reviewed_v1_to_v2_transition,true);assert.equal(u.legacy_guard_bytes_and_inode_preserved,true);assert.equal(u.legacy_guard_sha256,r.approved_legacy_guard_sha256.arm64);assert.equal(u.guard_program_sha256,r.signed_normal_release.arm64.guard_program);assert.equal(u.actual_loaded_service_conditions_verified,5);assert.equal(u.actual_candidate_ready_readonly_maintenance_observations,15);assert.equal(u.original_sql_tables_compared,21);assert.deepEqual(u.changed_protected_fields,[]);assert.equal(u.original_credentials_login_verified,true);assert.equal(u.proof_sha256,'323fd820b6e25b8efd0d5af5386ac6b45fc83a202b94ab40629660220720be71');
 assert.deepEqual(r.retained_previous_main_ci_failure,old.retained_main_ci_failure);assert.equal(r.retained_previous_main_ci_failure.resolved,false);assert.equal(r.actual_prior_normal_churn_failure.passed,false);assert.equal(r.actual_prior_normal_churn_failure.fail,67);assert.equal(r.actual_prior_normal_churn_failure.pass,233);assert.equal(r.retained_setup_failure.proof_created,false);assert.equal(r.pre_release_native_churn.pass,1000);
 assert.equal(r.previous_github_pr.main_ci_success,true);assert.equal(r.previous_github_pr.main_ci_pending,false);
 assert.equal(r.normal_build_python_tests,118);assert.equal(r.normal_build_python_skips,44);assert.equal(r.normal_build_node_gates,36);
 for(const k of ['normal_fresh_install_verified','older_main_original_development_retrofit_verified','current_native_failure_rollback_verified','cold_boot_orphan_interlock_verified','durable_interrupted_journal_recovery_complete','installer_death_during_constructor_verified','main_release_delivered','all_50_commercial'])assert.equal(r[k],false,k);
 assert.equal(c.commercial_feature_parity_complete,false);assert.equal(c.apps.length,50);assert.equal(r.main_auto_installed_new_apps,0);assert.equal(churn.main_changed,false);assert.equal(u.main_panel_changed,false);
});
