import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {createHash} from 'node:crypto';
const read=p=>readFile(new URL('../'+p,import.meta.url),'utf8');
const sha=s=>createHash('sha256').update(s).digest('hex');

test('ordinary production transaction is exact normal source and maintains independent native, fixture and failure evidence',async()=>{
 const inputs=JSON.parse(await read('panel-integration/release-source-inputs.json')),index=JSON.parse(await read('panel-integration/source-sha256.json'));
 const c=JSON.parse(await read('registry/functional-contracts.json')),r=c.reviewed_upgrade_transaction_release,current=c.reviewed_interlock_release;
 assert.equal(r.release,'0.1.0-dev.proapps24transactionbegh');assert.equal(r.frozen_source_files,16855);assert.equal(r.exported_normal_source_files,1207);
 assert.equal(inputs.frozen_inputs_sha256,current.frozen_inputs_sha256);assert.equal(inputs.archive_sha256,current.signed_normal_release.amd64.archive);assert.equal(Object.keys(index.files).length,1223);assert.equal(Object.keys(index.test_overrides??{}).length,0);assert.equal(r.source_overrides,0);assert.equal(current.source_overrides,0);
 for(const file of ['cmd/panel/main.go','cmd/executor/main.go','internal/upgradeguard/guard.go','internal/upgradeguard/guard_test.go','packaging/install.sh','packaging/build-release.sh','packaging/upgrade-release.py','packaging/test_production_upgrade.py']){
  const digest=sha(await read('panel-integration/'+file));assert.equal(inputs.files[file],digest,file);assert.equal(index.files[file],digest,file);
 }
 assert.equal(r.signed_normal_release.arm64.upgrade_helper,'b8732bac82e8470d58671b82a74894e972826dde4eac1bcbe3605ae16a94ce10');assert.equal(current.signed_normal_release.arm64.upgrade_helper,sha(await read('panel-integration/packaging/upgrade-release.py')));
 assert.equal(r.normal_build_python_tests,68);assert.equal(r.normal_build_python_skips,16);assert.equal(r.normal_build_node_gates,36);assert.equal(r.normal_build_go_and_vet_passed_both_architectures,true);
 assert.equal(r.actual_normal_executor_companion.pass_count,637);assert.equal(r.actual_normal_executor_companion.skip_count,124);assert.equal(r.actual_normal_executor_companion.fail_count,0);assert.equal(r.actual_normal_executor_companion.installed_state_preserved,true);
 assert.equal(r.actual_private_capacity.records,2560);assert.equal(r.actual_private_capacity.bytes,384*1024*1024);assert.equal(r.actual_private_capacity.original_deadline_seconds,2);assert.equal(r.actual_private_capacity.deadline_relaxed,false);assert.equal(r.actual_private_capacity.cold_os_cache_verified,false);
 const u=r.actual_signed_production_upgrade,b=r.actual_signed_start_failure_rollback,f=r.retained_first_candidate_preflight;
 assert.equal(u.passed,true);assert.equal(u.installer_exit,0);assert.equal(u.protected_sql_tables,21);assert.deepEqual(u.protected_fields_changed,[]);assert.equal(u.actual_candidate_readonly_maintenance_samples,15);assert.equal(u.actual_nginx_master_preserved,true);
 assert.equal(u.proof_sha256,'8f62239b9ae0b5cda90d68c88cd430ee8cbe73407d412f7ff1e896af1fb2fa7f');assert.match(u.scope,/pre-mutation baseline persisted/);
 assert.equal(b.passed,true);assert.equal(b.candidate_upgrade_accepted,false);assert.equal(b.installer_exit,1);assert.equal(b.protected_sql_tables_compared,21);assert.equal(b.normal_program_restored,r.release);assert.equal(b.actual_owned_fault_cleanup_complete,true);
 assert.equal(b.proof_sha256,'a7d9984eeda4af922cab25ea3a0a1ca10fd5eb455c3ed5153ba68cc5d851b543');assert.match(b.scope,/No schema migration, power loss or kill9 proof/);
 assert.equal(f.passed,true);assert.equal(f.upgrade_accepted,false);assert.equal(f.protected_state_and_program_pids_unchanged,true);assert.equal(f.proof_sha256,'9830cc034139699873968bbb815cfe9087a523397709a8cc4513eddbebe4c3b8');
 assert.equal(r.actual_linux_root_transaction_fixtures.tests,12);assert.match(r.actual_linux_root_transaction_fixtures.runner,/not native systemd acceptance/);
 assert.equal(r.retained_repository_pin_fixture_failure.failures,14);assert.equal(r.retained_repository_pin_fixture_failure.log_sha256,'46094f274401680a584536ce2e3e64da8e3de695515ad6dc17304b7793dceb04');
 const installer=await read('panel-integration/packaging/install.sh'),helper=await read('panel-integration/packaging/upgrade-release.py');
 assert(installer.indexOf('exec python3 "$HERE/upgrade-release.py" run "$HERE"')<installer.indexOf('getent group panel'));
 for(const text of ["QUEUES = ('jobs', 'runtime_jobs', 'mysql_jobs', 'acme_orders')","self.lock(self.releases/'.release.lock', create=True)","self.lock(self.path('/var/lib/panel-executor/runtime-lifecycle.lock'))","self.stop_writers()","self.queue_check()","self.journal('writers-stopped')","self.journal('database-backed-up')","self.journal('program-swapped')","self.journal('rolled-back')","self.journal('committed')","signal.signal(signal.SIGTERM","signal.signal(signal.SIGINT","backup changed during bounded streaming restore"])assert(helper.includes(text),text);
 for(const text of ['apt-get','rmtree',"'enable'","'restart'","add_argument('--root'"])assert(!helper.includes(text),text);
 assert(helper.indexOf('self.stop_writers()')<helper.indexOf("source.backup(destination)"));assert(helper.indexOf("self.journal('database-backed-up')")<helper.indexOf('self.switch(str(self.destination))'));
 const gate=await read('panel-integration/internal/upgradeguard/guard.go');
 for(const text of ['/.program-upgrade.pending','r.Method == http.MethodGet','r.URL.Path == path','http.StatusServiceUnavailable','Retry-After','no-store','ctx.Err() != nil'])assert(gate.includes(text),text);
 assert((await read('panel-integration/cmd/panel/main.go')).includes('upgradeguard.Handler(app, "/api/ready")'));assert((await read('panel-integration/cmd/executor/main.go')).includes('upgradeguard.Handler(handler, "/v1/overview", "/v1/health")'));
 const workflow=await read('.github/workflows/verify.yml');assert(workflow.includes("sudo python3 -B -m unittest discover -s panel-integration/packaging -p 'test_production_upgrade.py'"));assert(workflow.includes('test -race ./internal/upgradeguard -count=1'));
 assert.equal(r.original_public_key_sha256,'4ccfcc861d56a41e3ba7f7ace7e2432c815f366c58448d783df92c6632f01339');assert.equal(r.original_signed_verifier_sha256,'fe128e82b4e11345b320cd782134768bfe1a4df14947c425d7494873a7a7b7b5');
 assert.equal(r.main_release_delivered,false);assert.equal(r.actual_main_release,c.reviewed_normal_release.release);assert.equal(c.reviewed_normal_release.main_release_delivered,true);assert.equal(r.main_auto_installed_new_apps,0);assert.equal(c.commercial_feature_parity_complete,false);assert.equal(r.all_50_commercial,false);
 assert(r.remaining_gaps.some(s=>s.includes('kill9')));assert(r.remaining_gaps.some(s=>s.includes('two-architecture')));assert(r.remaining_gaps.some(s=>s.includes('file-backed')));
});
