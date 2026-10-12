import test from 'node:test';import assert from 'node:assert/strict';import {readFile} from 'node:fs/promises';import {createHash} from 'node:crypto';
const read=p=>readFile(new URL('../'+p,import.meta.url),'utf8'),sum=b=>createHash('sha256').update(b).digest('hex');
test('normal BECJ captures actual development migration safety and all its guard fixtures, not post-release overrides',async()=>{
 const index=JSON.parse(await read('panel-integration/source-sha256.json')),release=JSON.parse(await read('panel-integration/release-source-inputs.json'));
 assert.equal(release.frozen_inputs_sha256,'318f424f3e7902afc3669045b5d802cf4a234b80d22f7daba4604310a2dacfc7');assert.equal(Object.keys(index.test_overrides??{}).length,0);
 for(const f of ['scripts/upgrade-running-development.sh','packaging/test_development_upgrade_safety.py','packaging/test_native_build_directories.py']){const digest=sum(await read('panel-integration/'+f));assert.equal(index.files[f],digest);assert.equal(release.files[f],digest);}
 const migration=await read('panel-integration/scripts/upgrade-running-development.sh');
 assert.equal(sum(migration),'5c8d1aef32094d3bbb689a646f7264b9f71596ba0c762eb6429234a217b4b997');
 assert(migration.includes('for queue in jobs runtime_jobs; do'));assert(migration.includes('for pending in /opt/panel/web.new /opt/panel/bin/panel.new /opt/panel/bin/panel-executor.new; do'));
 const stop=migration.indexOf('SERVICES_STOPPED=1\nsystemctl stop panel panel-executor\ncheck_queues\nsqlite3'),swap=migration.indexOf('CHANGED=1\n');assert(stop>=0&&swap>stop);
 assert.match(migration,/elif \(\(result != 0 && SERVICES_STOPPED\)\); then/);assert(migration.includes('systemctl restart panel-executor panel || true'));assert(migration.includes('failed-development-release'));assert(migration.includes('return "$result"'));
 assert(migration.includes('nginx -t'));assert(migration.includes('PRAGMA integrity_check;'));assert.doesNotMatch(migration,/rm -rf|apt-get|--no-services/);
 const fixture=await read('panel-integration/packaging/test_development_upgrade_safety.py');assert.equal((fixture.match(/^    def test_/gm)||[]).length,4);assert(fixture.includes('guard fixture, not a live production job or upgrade proof'));
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
 const catalog=JSON.parse(await read('dist/catalog-v1.json'));assert.equal(catalog.apps.length,50);assert.equal(sum(JSON.stringify(catalog.apps.filter(a=>a.id!=='load-balance').sort((a,b)=>a.id.localeCompare(b.id)))),'c31316553d4408fadb4abbbd449a497d0832ed3d9f1d51c011a01ea8cc5089fd');
 assert.equal(sum(await read('dist/apps/load-balance/1.8.2/manifest.json')),'555f2ef5298758338917f44f65cb925751d4ce0082cb2cc4a998fc4decb7e69c');assert.equal(sum(await read('dist/apps/task-manager/1.2.1/manifest.json')),'99d3fd64c47b6b8983ac81eb413c08e70a557f03f9a85059b70f7b0a9c44d219');
 const c=JSON.parse(await read('registry/functional-contracts.json'));assert.equal(c.reviewed_normal_release.main_release_delivered,true);assert.equal(c.previous_load_alert_release.main_release_delivered,true);assert.equal(c.previous_main_delivery.release,'0.1.0-dev.proapps24devsafetybecj');assert.equal(c.previous_main_delivery.main_release_delivered,true);
});
