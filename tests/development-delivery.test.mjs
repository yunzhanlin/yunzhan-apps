import {catalogBeforeStatistics241} from './previous-statistics-catalog.mjs';
import test from 'node:test';import assert from 'node:assert/strict';import {readFile} from 'node:fs/promises';import {createHash} from 'node:crypto';
const read=p=>readFile(new URL('../'+p,import.meta.url),'utf8'),sum=b=>createHash('sha256').update(b).digest('hex');
test('normal BEIW strict development transaction and startup guard are exact frozen source, not prior Main delivery',async()=>{
 const index=JSON.parse(await read('panel-integration/source-sha256.json')),release=JSON.parse(await read('panel-integration/release-source-inputs.json'));
 assert.equal(release.frozen_inputs_sha256,'918458c33fde22e77952d50b9a976bf124321b4106c4e9ec366b67edf4be24d0');assert.equal(Object.keys(index.test_overrides??{}).length,0);
 for(const f of ['scripts/upgrade-running-development.sh','packaging/development-upgrade.py','packaging/upgrade-release.py','packaging/test_development_upgrade_safety.py','packaging/test_native_build_directories.py','cmd/panel/main.go','cmd/executor/main.go','internal/upgradeguard/guard.go','internal/upgradeguard/startup_linux.go','internal/upgradeguard/startup_linux_test.go','internal/upgradeguard/startup_other.go']){const digest=sum(await read('panel-integration/'+f));assert.equal(index.files[f],digest,f);assert.equal(release.files[f],digest,f);}
 const migration=await read('panel-integration/scripts/upgrade-running-development.sh'),helper=await read('panel-integration/packaging/development-upgrade.py'),production=await read('panel-integration/packaging/upgrade-release.py');
 assert.equal(sum(migration),'b116481c2a3d4e95922884d10f4baeb5ed4a828d902231fb0202eb25a9da8695');
 assert(migration.includes('exec /usr/bin/python3 "$RELEASE_PATH/development-upgrade.py" run "$RELEASE_PATH"'));assert(migration.indexOf('verify-release.sh')<migration.indexOf('exec /usr/bin/python3'));
 assert.doesNotMatch(migration,/^\s*(?:source|\.)\s+/m);
 for(const text of ["QUEUES = ('jobs', 'runtime_jobs', 'mysql_jobs', 'acme_orders')","'--check-program-upgrade-queues', timeout=10","self.authorize_startup()"])assert(production.includes(text),text);
 for(const text of ['self.stop_timer()','self.stop_writers()','self.tree_intents.append(name)',"self.journal('switching-'+name)",'self.replaced_units[source.name] = data','self.restore_database()','candidate accepted job changes; database rollback refused','development tree changed outside transaction; rollback refused',"self.journal('rolled-back')",'self.verify_states()'])assert(helper.includes(text),text);
 assert(helper.indexOf('self.stop_writers()')<helper.indexOf('source.backup(destination)'));assert(helper.indexOf("self.journal('database-backed-up')")<helper.indexOf("os.rename(self.base/name"));
 for(const text of ['useradd','apt-get','rm -rf','|| true',"'restart'","add_argument('--root'"])assert(!(helper+migration).includes(text),text);
 const fixture=await read('panel-integration/packaging/test_development_upgrade_safety.py');assert.equal((fixture.match(/^    def test_/gm)||[]).length,32);assert(fixture.includes('test_direct_helper_refuses_relative_and_traversing_release_before_commands'));assert(fixture.includes('not native systemd proof'));assert(fixture.includes('test_failure_between_bin_renames_recovers_original_tree_without_overwrite'));assert(fixture.includes('test_each_start_is_bound_to_live_owner_lease_and_exact_selected_program_bytes'));assert(fixture.includes('test_shared_failed_writer_with_control_process_does_not_reset_or_restore_any_tree'));
 const panel=await read('panel-integration/cmd/panel/main.go');assert(panel.indexOf('upgradeguard.CheckStartup()')<panel.indexOf('core.OpenStore('));assert(panel.indexOf('upgradeguard.CheckStartup()')<panel.indexOf('store.Recover()'));
});
test('scoped Main delivery and active PM2 graceful cold boot remain separate from incomplete all50 commercial acceptance',async()=>{
 const c=JSON.parse(await read('registry/functional-contracts.json')),r=c.previous_main_delivery;assert.equal(c.commercial_feature_parity_complete,false);assert.equal(r.all_50_commercial,false);
 assert.equal(r.release,'0.1.0-dev.proapps24devsafetybecj');assert.equal(r.frozen_source_files,16836);assert.equal(r.main_release_delivered,true);assert.equal(r.original_main_installed_app_count,12);assert.equal(r.main_auto_installed_new_apps,0);
 assert.equal(r.actual_main_program_delivery_proof_sha256,'291119322d577667b446ebdef873fce9312652bcf16d890a53764f819d5a08c3');
 assert.equal(r.actual_main_direct_origin_browser_proof_sha256,'e3667b8ebbbebae4e8cba01751d56210ce6d7913e50bff5bda2dc3839b17855e');
 assert.equal(r.actual_main_task_update_proof_sha256,'6355284beb0e908f6bd79bd399e4c568ac2e3b96892cddd1f30fc5990f411180');
 assert.equal(r.retained_failed_main_update_wrapper_sha256,'f4a19bf2efdfcc523d9ffc38577cc36b74be561e5267b110239e503d1e6ac93a');
 assert.match(r.real_qa_scope,/Not all50 commercial, full OS\/architecture matrix, sudden power loss, soak, native physical mobile or full CMS acceptance/);
 const pm2=c.apps.find(x=>x.id==='pm2-manager');assert(pm2.scenarios.some(x=>x.includes('BECG')&&x.includes('启动计数1→2')));assert(pm2.gaps.some(x=>x.includes('突然断电')&&x.includes('长时稳定性')));
 const task=c.apps.find(x=>x.id==='task-manager');assert(task.boundaries.some(x=>x.includes('verified-cache')&&x.includes('原严格来源封装失败同样保留')));assert(task.boundaries.some(x=>x.includes('真实更新不能用面板程序升级代替')));
});
test('new load-balance publication preserves previous Main scope and other49 immutable catalog identities',async()=>{
 const catalog=await catalogBeforeStatistics241(JSON.parse(await read('dist/catalog-v1.json')));assert.equal(catalog.apps.length,50);assert.equal(sum(JSON.stringify(catalog.apps.filter(a=>a.id!=='load-balance').sort((a,b)=>a.id.localeCompare(b.id)))),'c31316553d4408fadb4abbbd449a497d0832ed3d9f1d51c011a01ea8cc5089fd');
 assert.equal(sum(await read('dist/apps/load-balance/1.8.2/manifest.json')),'555f2ef5298758338917f44f65cb925751d4ce0082cb2cc4a998fc4decb7e69c');assert.equal(sum(await read('dist/apps/task-manager/1.2.1/manifest.json')),'99d3fd64c47b6b8983ac81eb413c08e70a557f03f9a85059b70f7b0a9c44d219');
 const c=JSON.parse(await read('registry/functional-contracts.json'));assert.equal(c.reviewed_normal_release.main_release_delivered,true);assert.equal(c.previous_load_alert_release.main_release_delivered,true);assert.equal(c.previous_main_delivery.release,'0.1.0-dev.proapps24devsafetybecj');assert.equal(c.previous_main_delivery.main_release_delivered,true);
});
