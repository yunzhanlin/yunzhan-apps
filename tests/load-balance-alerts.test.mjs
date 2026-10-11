import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {createHash} from 'node:crypto';
const read=p=>readFile(new URL('../'+p,import.meta.url),'utf8'),sum=b=>createHash('sha256').update(b).digest('hex');
test('load-balance1.8.3 alert handlers, source fixtures and UI gate match the exact normal BECV inputs',async()=>{
 const i=JSON.parse(await read('panel-integration/source-sha256.json')),r=JSON.parse(await read('panel-integration/release-source-inputs.json'));
 assert.equal(r.frozen_inputs_sha256,'234bd8c2ee1a24c7a2b517d8ff71e9e0994ee9d40118a3a854cdc0c1a4f638e3');assert.equal(r.archive_sha256,'3641e0027dee1133f770000382fcba743ac992420a661c86886afa42436617bb');
 assert.equal(Object.keys(i.files).length,1193);assert.equal(Object.keys(i.test_overrides??{}).length,0);
 for(const f of ['internal/core/outbound_load_balance.go','internal/core/outbound_load_balance_test.go','internal/core/outbound_notifications.go','internal/core/outbound_worker.go','internal/executor/app_load_balance_alert_linux.go','internal/executor/app_load_balance_alert_linux_test.go','internal/executor/app_notification_events_linux.go','web/src/OutboundNotifications.vue','web/src/AppModuleManager.vue','scripts/test-load-balance-alerts.mjs','packaging/build-release.sh']){
  const hash=sum(await read('panel-integration/'+f));assert.equal(i.files[f],hash,f);assert.equal(r.files[f],hash,f);
 }
 const build=await read('panel-integration/packaging/build-release.sh');assert(build.includes('scripts/test-load-balance-alerts.mjs'));
});
test('alert source is read-only, version-closed and all entry cursors advance in a single transaction with bounded capacity',async()=>{
 const source=await read('panel-integration/internal/executor/app_load_balance_alert_linux.go');
 assert(source.includes('version != "1.8.3"'));assert(source.includes('s.lockWAFObservation()'));assert(source.includes('s.loadBalanceHistorySharedPending()'));assert(source.includes('s.readLoadBalanceHTTPState(v, now)'));assert(source.includes('r.URL.RawQuery != ""'));
 assert.doesNotMatch(source,/Config\.Run|probeLoadBalance|applyLoadBalance|os\.WriteFile|moduleWrite/);
 const core=await read('panel-integration/internal/core/outbound_load_balance.go');
 for(const v of ['INSERT OR IGNORE INTO schema_migrations VALUES(44','count >= 4096','count >= 10000','defer tx.Rollback()','return tx.Commit()','revision > entry.Revision','sequence > entry.Sequence','first > sequence+1','if initial || revision != entry.Revision'])assert(core.includes(v),v);
 assert.equal((await read('panel-integration/internal/core/outbound_load_balance_test.go')).match(/^func Test/gm).length,8);
 assert.equal((await read('panel-integration/internal/executor/app_load_balance_alert_linux_test.go')).match(/^func Test/gm).length,3);
});
test('new signed manifest retains immutable1.8.2 and other49 identities; original limits and old subscriptions do not silently expand',async()=>{
 const catalog=JSON.parse(await read('dist/catalog-v1.json')),item=catalog.apps.find(x=>x.id==='load-balance'),manifest=JSON.parse(await read('dist/apps/load-balance/1.8.3/manifest.json'));
 assert.equal(item.version,'1.8.3');assert.equal(sum(await read('dist/apps/load-balance/1.8.3/manifest.json')),item.sha256);assert.equal(sum(await read('dist/apps/load-balance/1.8.2/manifest.json')),'555f2ef5298758338917f44f65cb925751d4ce0082cb2cc4a998fc4decb7e69c');
 assert.equal(sum(JSON.stringify(catalog.apps.filter(a=>a.id!=='load-balance').sort((a,b)=>a.id.localeCompare(b.id)))),'c31316553d4408fadb4abbbd449a497d0832ed3d9f1d51c011a01ea8cc5089fd');
 assert.equal(catalog.apps.length,50);assert.equal(manifest.capabilities.length,12);assert(manifest.capabilities.every(s=>s.length<=64));assert(manifest.summary.length<=240);
 assert(manifest.capabilities.some(s=>s.includes('旧通道不自动开启')));assert(manifest.capabilities.some(s=>s.includes('健康确认非整体恢复')));
 const view=await read('panel-integration/web/src/OutboundNotifications.vue');assert(view.includes('kinds: ["integrity", "sync", "daily"]'));assert(view.includes('{ id: "load-balance", label: "负载均衡健康变化与事件缺口" }'));
});
test('scoped actual Main and installed alert proofs do not substitute for all50, physical mobile or full matrix acceptance',async()=>{
 const c=JSON.parse(await read('registry/functional-contracts.json')),r=c.reviewed_normal_release,lb=c.apps.find(x=>x.id==='load-balance');
 assert.equal(r.release,'0.1.0-dev.proapps24loadalertbecv');assert.equal(r.main_release_delivered,true);assert.equal(r.all_50_commercial,false);assert.equal(c.commercial_feature_parity_complete,false);
 assert.equal(r.original_sql_tables_compared,14);assert.equal(r.actual_main_program_delivery_proof_sha256,'f0ae62bd9bea2fc3e504c4e767ff36e60b3efa9a31dd3144bfe06c2c8765563e');assert.equal(r.actual_main_direct_origin_browser_proof_sha256,'6f1b0659c26e1ab20502b0ea9aff2e4ed45b55311cb0ad00a7ea38f2a4806908');assert.equal(r.main_auto_installed_new_apps,0);assert.equal(r.original_main_site_count,58);const a=r.installed_load_balance_alert_acceptance;assert.equal(a.actual_job_id,'284ea23ad7593c2377aa7544bf813357');assert.equal(a.actual_business_followup_proof_sha256,'2aa82768aeb5567e0477939e6cfc43a37e7e4a1df10296a045617e1775ec97d6');assert.equal(a.actual_browser_proof_sha256,'a3c238084f0f8186c266b0edf5c00358de948236a681525429c5c4ffb0a4f87e');assert.equal(a.real_browser_checks,41);assert.equal(a.retained_browser_failures.length,4);assert.match(a.scope,/not lost pre-BEDF|original readiness-race/);assert.match(a.scope,/no Main Load Balance installation/);assert.equal(r.actual_becv_upgrade_proof_sha256,'7a0882108106db61b833f454abe6c4da5afa916312fa6deafbfe6b8453316924');
 assert.equal(c.previous_main_delivery.release,'0.1.0-dev.proapps24devsafetybecj');assert.equal(c.previous_main_delivery.main_release_delivered,true);
 assert(lb.gaps.some(s=>s.includes('其余主流系统/架构')&&s.includes('仍待完成')));assert(lb.gaps.some(s=>s.includes('自动流量执行结果')&&s.includes('仍未实现')));assert(lb.gaps.some(s=>s.includes('TCP/UDP')));
 assert(lb.boundaries.some(s=>s.includes('单节点达到健康阈值不代表全部节点恢复')));assert(lb.scenarios.some(s=>s.includes('124项特定原生环境跳过')));
});
