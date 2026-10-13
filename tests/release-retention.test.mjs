import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {createHash} from 'node:crypto';
const read=p=>readFile(new URL('../'+p,import.meta.url),'utf8');
const sha=s=>createHash('sha256').update(s).digest('hex');

test('release cleanup uses exact normal source and keeps native fixtures, real preview and rejected candidates independent',async()=>{
 const c=JSON.parse(await read('registry/functional-contracts.json')),r=c.reviewed_release_retention_release,current=c[c.current_reviewed_release];
 const inputs=JSON.parse(await read('panel-integration/release-source-inputs.json')),index=JSON.parse(await read('panel-integration/source-sha256.json'));
 assert.equal(r.release,'0.1.0-dev.proapps24retentionbegx');assert.equal(r.frozen_source_files,16857);assert.equal(r.exported_normal_source_files,1209);assert.equal(r.source_overrides,0);
 assert.equal(inputs.frozen_inputs_sha256,current.frozen_inputs_sha256);assert.equal(inputs.archive_sha256,current.signed_normal_release.amd64.archive);assert.equal(Object.keys(index.files).length,1250);assert.equal(Object.keys(index.test_overrides??{}).length,0);
 const f=r.actual_linux_root_cleanup_fixtures;
 assert.equal(f.passed,true);assert.equal(f.tests,21);assert.equal(f.skips,0);assert.equal(f.actual_native_private_bind_mount_case_ran,true);assert.equal(f.actual_qa_program_gateway_and_lock_preserved,true);assert.equal(f.host_installation_pruned,false);
 for(const [file,expected] of Object.entries(f.input_sha256)){
  const digest=sha(await read('panel-integration/packaging/'+file));
  // BEGX fixture inputs remain historical; the normal BEHW builder also emits
  // the separately pinned Linux startup companion and development helper.
  if(file==='build-release.sh')assert.equal(expected,'ede25bb13dd5892305fd820ab5b02d911a36598398b88f406d5f3673f46d4074');
  else if(file==='install.sh')assert.equal(expected,'aa4ed60dc324406da11d57b129709e74d18edb87d0dbe3616f98fb29b0af4cec');
  else assert.equal(digest,expected,file);
  assert.equal(inputs.files['packaging/'+file],digest,file);assert.equal(index.files['packaging/'+file],digest,file);
 }
 assert.equal(f.proof_sha256,'2ab2b4b994487952ebcbc5b809bac34ed7f0e1d13c32996ce22c47fb97aa170c');
 assert.equal(r.normal_build_go_and_vet_passed_both_architectures,true);assert.equal(r.normal_build_python_tests,89);assert.equal(r.normal_build_python_skips,18);assert.equal(r.normal_build_node_gates,36);
 for(const arch of ['amd64','arm64']){
  assert.equal(r.signed_normal_release[arch].prune_helper,f.input_sha256['prune-releases.py']);
  assert.equal(r.signed_normal_release[arch].upgrade_helper,c.reviewed_upgrade_transaction_release.signed_normal_release[arch].upgrade_helper);
  assert.equal(r.signed_normal_release[arch].panel,c.reviewed_upgrade_transaction_release.signed_normal_release[arch].panel);
  assert.equal(r.signed_normal_release[arch].executor,c.reviewed_upgrade_transaction_release.signed_normal_release[arch].executor);
 }
 const n=r.actual_normal_executor_companion,p=r.actual_signed_readonly_real_inventory_preview;
 assert.equal(n.passed,true);assert.equal(n.pass_count,637);assert.equal(n.skip_count,124);assert.equal(n.fail_count,0);assert.equal(n.installed_state_preserved,true);assert.equal(n.source_inputs_sha256,r.frozen_inputs_sha256);
 assert.equal(n.proof_sha256,'ec71048e14f46d1045c35a53cc4dd87f9d91be25bf1a252646a93607ecdf38f7');
 assert.equal(p.passed,true);assert.equal(p.preview_exit,0);assert.equal(p.actual_original_key_signature_verified,true);assert.equal(p.actual_legacy_all_programs_retained,true);assert.equal(p.protected_state_preserved,true);assert.equal(p.protected_original_sql_tables,21);assert.equal(p.host_installation_pruned,false);assert.equal(p.candidate_program_installed,false);
 assert.equal(p.proof_sha256,'78bca0a559f272cb256ea737b4a5124021088da003ee4339048fb9f319a478b8');assert.match(p.preview_summary,/candidates=0 bytes=0 mode=preview$/);
 assert.equal(r.private_complete_inventory.records,2560);assert.equal(r.private_complete_inventory.bytes,384*1024*1024);assert.equal(r.private_complete_inventory.original_deadline_seconds,2);assert.equal(r.private_complete_inventory.deadline_relaxed,false);assert.equal(r.private_complete_inventory.cold_os_cache_verified,false);
 const first=r.retained_first_candidate;
 assert.equal(first.release,'0.1.0-dev.proapps24retentionbegt');assert.equal(first.native_cleanup_fixtures.tests,20);assert.equal(first.normal_executor_companion.fail_count,0);assert.equal(first.legacy_reference_acceptance_passed,false);assert.equal(first.legacy_reference_test_failures,2);
 assert.equal(first.legacy_reference_failure_log_sha256,'e664bafc478fa469389f9d569d011eb730b216a5230d45df399f846aaeceb3d2');assert.notEqual(first.frozen_inputs_sha256,r.frozen_inputs_sha256);
 assert.equal(r.retained_first_host_fixture_failure.failures,4);assert.equal(r.retained_first_host_fixture_failure.errors,1);assert.equal(r.retained_first_native_bootstrap_failure.tests_executed,false);assert.equal(r.retained_first_native_bootstrap_failure.installed_state_mutations,false);assert.equal(r.retained_repository_pin_fixture_failure.failures,15);
 const prior=r.previous_upgrade_transaction_github_pr;assert.equal(prior.ci.passed,true);assert.equal(prior.ci.head,prior.head);assert.equal(prior.main_ci_pending,false);assert.equal(prior.main_ci.passed,true);assert.equal(prior.main_ci.head,prior.merge);
 const helper=await read('panel-integration/packaging/prune-releases.py'),wrapper=await read('panel-integration/packaging/prune-releases.sh'),fixture=await read('panel-integration/packaging/test_prune_releases.py');
 for(const text of ["fcntl.LOCK_EX if apply else fcntl.LOCK_SH",'fcntl.LOCK_NB','os.O_NOFOLLOW','os.O_NONBLOCK','duplicate recovery journal field','MAX_ENTRIES = 100000','1024','2048','self.current_version()[1] != current','latest_evidence != evidence','shutil.rmtree.avoids_symlink_attacks',"self.mounted_paths()","/proc/self/mountinfo",'do not traverse it','if self.legacy_backups:',"protected.update((version, previous_path.name))","self.tree(self.releases/name, self.mounted_paths())[0] != snapshot"]){assert(helper.includes(text),text);}
 assert(wrapper.includes('exec python3 "$HERE/prune-releases.py" "$@"'));assert(!wrapper.includes('rm -rf'));assert(!helper.includes('os.chmod'));assert(!helper.includes('O_CREAT'));
 assert(helper.indexOf('self.acquire(apply)')<helper.indexOf('version, current, protected, evidence, candidates = self.plan()'));assert(helper.indexOf('latest_evidence != evidence')<helper.indexOf('shutil.rmtree(self.releases/name)'));
 for(const text of ['test_actual_private_bind_mount_refuses_all_deletion',"['/usr/bin/mount','--bind'", "['/usr/bin/umount'",'not a passing mount proof','test_legacy_backup_without_previous_program_reference_retains_every_release','test_replaced_lock_path_after_plan_never_uses_old_descriptor_as_new_lease'])assert(fixture.includes(text),text);
 const workflow=await read('.github/workflows/verify.yml');assert(workflow.includes("sudo python3 -B -m unittest discover -s panel-integration/packaging -p 'test_prune_releases.py'"));
 assert.equal(r.original_public_key_sha256,'4ccfcc861d56a41e3ba7f7ace7e2432c815f366c58448d783df92c6632f01339');assert.equal(r.original_signed_verifier_sha256,sha(await read('panel-integration/packaging/signed-release.py')));
 assert.equal(r.main_release_delivered,false);assert.equal(r.actual_main_release,c.reviewed_normal_release.release);assert.equal(r.actual_qa_program_release,c.reviewed_upgrade_transaction_release.release);assert.equal(r.main_auto_installed_new_apps,0);assert.equal(r.all_50_commercial,false);assert.equal(c.commercial_feature_parity_complete,false);
 assert(r.remaining_gaps.some(s=>s.includes('kill9')));assert(r.remaining_gaps.some(s=>s.includes('file-backed')));assert(r.remaining_gaps.some(s=>s.includes('schema-changing')));
});
