import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {createHash} from 'node:crypto';
const read=p=>readFile(new URL('../'+p,import.meta.url),'utf8'),sha=b=>createHash('sha256').update(b).digest('hex');

test('independent immutable service interlock has exact normal source, separate native upgrade proofs and explicit remaining recovery gaps',async()=>{
 const c=JSON.parse(await read('registry/functional-contracts.json')),r=c.reviewed_interlock_release,current=c.reviewed_lease_release;
 const i=JSON.parse(await read('panel-integration/source-sha256.json')),f=JSON.parse(await read('panel-integration/release-source-inputs.json'));
 assert.equal(r.release,'0.1.0-dev.proapps24interlockbejc');assert.equal(r.frozen_source_files,16871);assert.equal(r.exported_normal_source_files,1223);assert.equal(r.exported_build_input_files,1182);
 assert.equal(current.frozen_inputs_sha256,f.frozen_inputs_sha256);assert.equal(current.signed_normal_release.amd64.archive,f.archive_sha256);assert.equal(Object.keys(i.files).length,1224);assert.equal(Object.keys(f.files).length,1183);assert.equal(Object.keys(i.test_overrides??{}).length,0);assert.equal(r.source_overrides,0);
 for(const name of ['cmd/startguard/main.go','internal/upgradeguard/service_startup_linux.go','internal/upgradeguard/service_startup_other.go','internal/upgradeguard/service_startup_linux_test.go','packaging/start-guard-install.py','packaging/test_start_guard_install.py']){
  const digest=sha(await read('panel-integration/'+name));assert.equal(i.files[name],digest);assert.equal(f.files[name],digest);
 }
 const gate=await read('panel-integration/internal/upgradeguard/service_startup_linux.go');
 for(const text of ['CheckServiceStartup(unit string)','startupService(unit)','serviceMarkerBlocked(path)','recovery && pending != ""','selectedServiceProgram(kind, pending)','serviceStartupAt(pending, lock, program, kind)','st.Mode&07777 != 0755','st.Nlink != 1','st.Uid != 0','unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC','sameStartupStat(before, after)','startupVerifyAt(marker, lock','filepath.Dir(target) != releases','startupVersion.MatchString(filepath.Base(target))'])assert(gate.includes(text),text);
 for(const text of ['os.Remove','os.Chmod','os.WriteFile','os.Getenv','exec.Command'])assert(!gate.includes(text),text);
 const entry=await read('panel-integration/cmd/startguard/main.go');assert(entry.includes('len(os.Args) != 2'));assert(entry.includes('os.Exit(255)'));assert(!entry.includes('core.OpenStore'));assert(!entry.includes('executor.New'));
 const install=await read('panel-integration/packaging/start-guard-install.py');assert(install.includes("GUARD = '/usr/lib/panel-program-upgrade/start-guard-v2'"));assert(install.includes("LEGACY = '/usr/lib/panel-program-upgrade/start-guard-v1'"));assert(install.includes('ExecCondition=+'));assert(install.includes('immutable v2 cannot overwrite'));assert(install.indexOf('targets = inventory(transaction)')<install.indexOf('target.parent.mkdir'));assert(!install.includes("'enable'"));assert(!install.includes("'restart'"));
 const helper=await read('panel-integration/packaging/upgrade-release.py'),development=await read('panel-integration/packaging/development-upgrade.py');
 assert(helper.indexOf('self.start_guard(install=True)')<helper.indexOf('self.create_pending()\n'));assert(development.indexOf('self.start_guard(install=True)')<development.indexOf('self.create_pending()\n'));
 assert(helper.includes("'retained_on_rollback':True"));assert.equal(r.fixed_guarded_service_count,5);assert.equal(r.guard_condition_before_exec_start_pre,true);assert.equal(r.guard_retained_after_live_rollback_fixture,true);
 const n=r.actual_normal_native_fixtures;assert.equal(n.passed,true);assert.equal(n.executor_pass,663);assert.equal(n.executor_skip,124);assert.equal(n.executor_fail,0);assert.equal(n.startup_pass,9);assert.equal(n.startup_skip,1);assert.equal(n.python_count,40);assert.equal(n.python_skips,0);assert.equal(n.installed_state_preserved,true);assert.equal(n.candidate_installed,false);
 for(const p of [r.actual_native_development_positive,r.actual_native_production_positive]){assert.equal(p.passed,true);assert.equal(p.actual_loaded_service_conditions_verified,5);assert.equal(p.all_50_commercial,false);}
 assert.equal(r.actual_native_development_positive.actual_readonly_maintenance_samples,41);assert.equal(r.actual_native_production_positive.actual_candidate_ready_readonly_maintenance_observations,14);assert.equal(r.actual_native_production_positive.guard_program_sha256,r.signed_normal_release.arm64.guard_program);
 assert.equal(r.retained_pre_mutation_development_refusal.passed,false);assert.equal(r.retained_pre_mutation_development_refusal.root_artifact_created,false);
 assert.equal(r.historical_development_timeout_rollback.passed,true);assert.equal(r.historical_development_timeout_rollback.not_current_interlock_native_rollback_proof,true);assert.equal(r.historical_development_timeout_rollback.normal_archive_source_sha256,c.reviewed_quiescent_stop_release.frozen_inputs_sha256);
 assert.equal(r.previous_github_pr.main_ci_success,true);assert.equal(r.previous_github_pr.main_ci_pending,false);
 assert.equal(r.normal_build_python_tests,113);assert.equal(r.normal_build_python_skips,41);assert.equal(r.normal_build_node_gates,36);
 for(const field of ['normal_fresh_install_verified','current_interlock_native_failure_rollback_verified','older_main_binary_native_retrofit_verified','cold_boot_orphan_interlock_verified','durable_interrupted_journal_recovery_complete','installer_death_during_constructor_verified','main_release_delivered','all_50_commercial'])assert.equal(r[field],false,field);
 assert.equal(c.commercial_feature_parity_complete,false);assert.equal(c.apps.length,50);assert.equal(r.main_auto_installed_new_apps,0);assert(r.remaining_gaps.some(s=>s.includes('kill9/power-loss')));
 const workflow=await read('.github/workflows/verify.yml');assert(workflow.includes("sudo python3 -B -m unittest discover -s panel-integration/packaging -p 'test_start_guard_install.py'"));
});
