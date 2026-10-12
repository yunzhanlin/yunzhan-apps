import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {createHash} from 'node:crypto';
const read=p=>readFile(new URL('../'+p,import.meta.url),'utf8'),sum=b=>createHash('sha256').update(b).digest('hex');
test('load-balance1.8.5 health, traffic and source handlers match exact normal BEFA source',async()=>{
 const i=JSON.parse(await read('panel-integration/source-sha256.json')),r=JSON.parse(await read('panel-integration/release-source-inputs.json'));
 assert.equal(r.frozen_inputs_sha256,'e05d2d4f01d9600b7257b71dcebe4740c4c84c04440fc738e0c3c15c0535ec18');assert.equal(r.archive_sha256,'022038d5ca226e2992e7f7c30894844fd524049a78c6379ce20a1755d14effc9');
 assert.equal(Object.keys(i.files).length,1213);assert.equal(Object.keys(i.test_overrides??{}).length,0);
 for(const f of ['internal/core/outbound_load_balance.go','internal/core/outbound_load_balance_test.go','internal/core/outbound_load_balance_traffic.go','internal/core/outbound_load_balance_traffic_test.go','internal/core/outbound_notifications.go','internal/core/outbound_worker.go','internal/core/outbound_smtp.go','internal/executor/app_load_balance_alert_linux.go','internal/executor/app_load_balance_alert_linux_test.go','internal/executor/app_load_balance_traffic_alert_linux.go','internal/executor/app_load_balance_traffic_alert_linux_test.go','internal/executor/app_notification_events_linux.go','web/src/OutboundNotifications.vue','web/src/AppModuleManager.vue','scripts/test-load-balance-alerts.mjs','packaging/build-release.sh']){
  const hash=sum(await read('panel-integration/'+f));assert.equal(i.files[f],hash,f);assert.equal(r.files[f],hash,f);
 }
 const build=await read('panel-integration/packaging/build-release.sh');assert(build.includes('scripts/test-load-balance-alerts.mjs'));
});
test('alert source is read-only, version-closed and all entry cursors advance in a single transaction with bounded capacity',async()=>{
 const source=await read('panel-integration/internal/executor/app_load_balance_alert_linux.go');
 assert(source.includes('version != "1.8.3"'));assert(source.includes('s.lockWAFObservation()'));assert(source.includes('s.loadBalanceHistorySharedPending()'));assert(source.includes('s.readLoadBalanceHTTPState(v, now)'));assert(source.includes('r.URL.RawQuery != ""'));
 assert.doesNotMatch(source,/Config\.Run|probeLoadBalance|applyLoadBalance|os\.WriteFile|moduleWrite/);
 const core=await read('panel-integration/internal/core/outbound_load_balance.go');
 for(const v of ['INSERT OR IGNORE INTO schema_migrations VALUES(44','count >= 4096','count >= 10000','defer tx.Rollback()','if err = tx.Commit(); err != nil','revision > entry.Revision','sequence > entry.Sequence','first > sequence+1','if initial || revision != entry.Revision'])assert(core.includes(v),v);
 assert.equal((await read('panel-integration/internal/core/outbound_load_balance_test.go')).match(/^func Test/gm).length,8);
 assert.equal((await read('panel-integration/internal/executor/app_load_balance_alert_linux_test.go')).match(/^func Test/gm).length,3);
});
test('new signed manifest retains immutable1.8.2 and other49 identities; original limits and old subscriptions do not silently expand',async()=>{
 const catalog=JSON.parse(await read('dist/catalog-v1.json')),item=catalog.apps.find(x=>x.id==='load-balance'),manifest=JSON.parse(await read('dist/apps/load-balance/1.8.5/manifest.json'));
 assert.equal(item.version,'1.8.5');assert.equal(sum(await read('dist/apps/load-balance/1.8.5/manifest.json')),item.sha256);assert.equal(sum(await read('dist/apps/load-balance/1.8.4/manifest.json')),'696449c0199a870365459f603bcfd71e5a2f275a72e2230878e346894699c1ff');assert.equal(sum(await read('dist/apps/load-balance/1.8.3/manifest.json')),'588babcbc38cae9b2c1bf120acd9bfcb02482af1f3ce8ca1d1f740b38087cf13');assert.equal(sum(await read('dist/apps/load-balance/1.8.2/manifest.json')),'555f2ef5298758338917f44f65cb925751d4ce0082cb2cc4a998fc4decb7e69c');
 assert.equal(sum(JSON.stringify(catalog.apps.filter(a=>a.id!=='load-balance').sort((a,b)=>a.id.localeCompare(b.id)))),'c31316553d4408fadb4abbbd449a497d0832ed3d9f1d51c011a01ea8cc5089fd');
 assert.equal(catalog.apps.length,50);assert.equal(manifest.capabilities.length,12);assert(manifest.capabilities.every(s=>s.length<=64));assert(manifest.summary.length<=240);
 assert(manifest.capabilities.some(s=>s.includes('旧通道不扩大')));assert(manifest.summary.includes('来源重新可核对不代表业务恢复'));
 const view=await read('panel-integration/web/src/OutboundNotifications.vue');assert(view.includes('kinds: ["integrity", "sync", "daily"]'));assert(view.includes('{ id: "load-balance", label: "负载均衡健康变化与事件缺口" }'));
});
test('new traffic scope retains full private inventory, atomic cursors and qualified closed subtype summaries',async()=>{
 const native=await read('panel-integration/internal/executor/app_load_balance_traffic_alert_linux.go');
 for(const s of ['version != "1.8.4"','s.loadBalanceHistoryInventory(r.Context())','s.lockWAFObservation()','pendingMatched','bytes.Equal(a, b)','row.Archived','s.lbHealthWorkerCheckedAt'])assert(native.includes(s),s);
 assert.doesNotMatch(native,/Config\.Run|probeLoadBalance|applyLoadBalance|os\.WriteFile|moduleWrite/);
 const core=await read('panel-integration/internal/core/outbound_load_balance_traffic.go');
 for(const s of ['len(f.Records) > 2560','schema_migrations VALUES(45','count >= 10000','len(known) >= 4096','defer tx.Rollback()','if e = tx.Commit(); e != nil','if !initial || r.State == "pending"','load_balance_traffic_cursors','traffic_committed','traffic_recovered','traffic_pending','worker_observation'])assert(core.includes(s),s);
 assert.equal((await read('panel-integration/internal/core/outbound_load_balance_traffic_test.go')).match(/^func Test/gm).length,9);
 assert.equal((await read('panel-integration/internal/executor/app_load_balance_traffic_alert_linux_test.go')).match(/^func Test/gm).length,5);
 const queue=await read('panel-integration/internal/core/outbound_notifications.go');assert(queue.includes('x.n.Source = x.source'));
 const smtp=await read('panel-integration/internal/core/outbound_smtp.go');assert(smtp.includes('outboundDeliverySummary(d.Payload, "")'));const summary=await read('panel-integration/internal/core/outbound_delivery_summary.go');assert(summary.includes('outboundEventSource(source.Kind, source.EventType)'));
 const view=await read('panel-integration/web/src/OutboundNotifications.vue');assert(view.includes('{ id: "load-balance-traffic", label: "负载均衡切流事务与后台调度" }'));
 assert.equal((await read('panel-integration/scripts/test-load-balance-alerts.mjs')).match(/^test\(/gm).length,5);
 const c=JSON.parse(await read('registry/functional-contracts.json'));assert.equal(c.reviewed_normal_release.all_50_commercial,false);assert.equal(c.previous_traffic_release.actual_normal_executor_companion_passes,632);assert.equal(c.previous_traffic_release.actual_normal_executor_companion_skips,124);
 assert.equal(c.reviewed_normal_release.installed_load_balance_source_acceptance.actual_source_fault_retry_restart_pause_verified,true);
 assert(c.apps.find(a=>a.id==='load-balance').gaps.some(s=>s.includes('其他系统/架构')&&s.includes('仍待完成')));
});
test('scoped actual Main and installed alert proofs do not substitute for all50, physical mobile or full matrix acceptance',async()=>{
 const c=JSON.parse(await read('registry/functional-contracts.json')),r=c.previous_load_alert_release,lb=c.apps.find(x=>x.id==='load-balance');
 assert.equal(r.release,'0.1.0-dev.proapps24loadalertbecv');assert.equal(r.main_release_delivered,true);assert.equal(r.all_50_commercial,false);assert.equal(c.commercial_feature_parity_complete,false);
 assert.equal(r.original_sql_tables_compared,14);assert.equal(r.actual_main_program_delivery_proof_sha256,'f0ae62bd9bea2fc3e504c4e767ff36e60b3efa9a31dd3144bfe06c2c8765563e');assert.equal(r.actual_main_direct_origin_browser_proof_sha256,'6f1b0659c26e1ab20502b0ea9aff2e4ed45b55311cb0ad00a7ea38f2a4806908');assert.equal(r.main_auto_installed_new_apps,0);assert.equal(r.original_main_site_count,58);const a=r.installed_load_balance_alert_acceptance;assert.equal(a.actual_job_id,'284ea23ad7593c2377aa7544bf813357');assert.equal(a.actual_business_followup_proof_sha256,'2aa82768aeb5567e0477939e6cfc43a37e7e4a1df10296a045617e1775ec97d6');assert.equal(a.actual_browser_proof_sha256,'a3c238084f0f8186c266b0edf5c00358de948236a681525429c5c4ffb0a4f87e');assert.equal(a.real_browser_checks,41);assert.equal(a.retained_browser_failures.length,4);assert.match(a.scope,/not lost pre-BEDF|original readiness-race/);assert.match(a.scope,/no Main Load Balance installation/);assert.equal(r.actual_becv_upgrade_proof_sha256,'7a0882108106db61b833f454abe6c4da5afa916312fa6deafbfe6b8453316924');
 assert.equal(c.previous_main_delivery.release,'0.1.0-dev.proapps24devsafetybecj');assert.equal(c.previous_main_delivery.main_release_delivered,true);
 assert(lb.gaps.some(s=>s.includes('其余主流系统/架构')&&s.includes('仍待完成')));assert(lb.gaps.some(s=>s.includes('实际pending/recovered中断')&&s.includes('仍待完成')));assert(lb.gaps.some(s=>s.includes('TCP/UDP')));
 assert(lb.boundaries.some(s=>s.includes('单节点达到健康阈值不代表全部节点恢复')));assert(lb.scenarios.some(s=>s.includes('124项特定原生环境跳过')));
});
test('actual installed traffic and Main proof cohorts retain exact boundaries without changing signed packages or all50 claims',async()=>{
 const c=JSON.parse(await read('registry/functional-contracts.json')),r=c.previous_traffic_release,t=r.installed_load_balance_traffic_acceptance;
 assert.equal(r.release,'0.1.0-dev.proapps24trafficbedeu');assert.equal(r.main_release_delivered,true);assert.equal(r.all_50_commercial,false);assert.equal(r.original_main_sql_tables_compared,14);assert.equal(r.original_main_site_count,58);assert.equal(r.main_auto_installed_new_apps,0);
 assert.equal(r.actual_main_program_delivery_proof_sha256,'b9609e2034729a6ec43f0b4b318c0e912eec4364e10ef6c9e9fe5b687d751abc');assert.equal(r.actual_main_direct_origin_browser_proof_sha256,'9bc35bc5b636d178f82a5111354ae8d01908404a5c2fe43151813ce10fa143aa');assert.equal(r.actual_main_original_key_cache_independently_verified,true);
 assert.equal(t.version,'1.8.4');assert.equal(t.actual_update_job_id,'f90ac58468bc6d35750384db383c0cbf');assert.equal(t.actual_signed_ui_update_checks,43);assert.equal(t.actual_business_checks,7);assert.equal(t.actual_scope_browser_checks,42);assert.equal(t.actual_recovered_and_pending_business_verified,false);
 assert.equal(t.actual_business_proof_sha256,'5124cde1943a89fcf5d2b4b29b342e69cfe7761edc439d174bccf77562e51f8a');assert.equal(t.actual_scope_browser_proof_sha256,'930c01b214ce3f741842ca423e8a0e2561e9b5d021e5b1751ac134fa840ae453');assert.equal(t.retained_pre_browser_directory_mode_fixture_failure_sha256,'abb7e12e9c2703eeb4438292449588a8eca44230d554703dcc75a663a8b99b63');assert.match(t.scope,/no power loss/);assert.match(t.scope,/without LB installation/);
 assert.equal(r.actual_main_catalog_sha256,'fec282bbb2e0d10747e20a8982d07ffaabbf986003b882dc77ca70473a91f7bd');assert.equal(sum(await read('dist/apps/load-balance/1.8.4/manifest.json')),'696449c0199a870365459f603bcfd71e5a2f275a72e2230878e346894699c1ff');assert.equal(c.commercial_feature_parity_complete,false);
});
test('source availability scope, bounded reads and regenerated summaries are exact normal code, not business recovery claims',async()=>{
 const i=JSON.parse(await read('panel-integration/source-sha256.json')),r=JSON.parse(await read('panel-integration/release-source-inputs.json'));
 for(const f of ['internal/core/outbound_load_balance_source.go','internal/core/outbound_load_balance_source_test.go','internal/core/outbound_delivery_summary.go','internal/core/outbound_delivery_summary_test.go','web/src/outboundSourceView.ts','scripts/test-outbound-source-view.mjs']){const h=sum(await read('panel-integration/'+f));assert.equal(i.files[f],h);assert.equal(r.files[f],h);}
 const source=await read('panel-integration/internal/core/outbound_load_balance_source.go');for(const s of ['schema_migrations VALUES(46','if !subscribed','now < checked','notices >= 10000','return tx.Commit()','source_unavailable','source_ready'])assert(source.includes(s),s);
 const worker=await read('panel-integration/internal/core/outbound_worker.go');assert.equal((worker.match(/context.WithTimeout\(ctx, 2\*time.Second\)/g)||[]).length,2);assert(worker.includes('healthAvailable && trafficAvailable'));assert(worker.includes('bytes.NewReader(payload)'));assert(worker.includes('webhookSignature(credential.Secret, d.ID, timestamp, payload)'));
 const summary=await read('panel-integration/internal/core/outbound_delivery_summary.go');for(const s of ['outboundJSONUniqueKeys','DisallowUnknownFields','source.EventID != eventID','原推送事件状态与严重性不可核对'])assert(summary.includes(s));assert.equal((await read('panel-integration/internal/core/outbound_load_balance_source_test.go')).match(/^func Test/gm).length,6);assert.equal((await read('panel-integration/internal/core/outbound_delivery_summary_test.go')).match(/^func Test/gm).length,5);
 const c=JSON.parse(await read('registry/functional-contracts.json'));assert.equal(c.reviewed_normal_release.release,'0.1.0-dev.proapps24inventorybefm');assert.equal(c.reviewed_normal_release.main_release_delivered,true);assert.equal(c.previous_traffic_release.main_release_delivered,true);assert.equal(c.commercial_feature_parity_complete,false);assert.equal(c.reviewed_normal_release.all_50_commercial,false);
 assert.equal(sum(await read('dist/catalog-v1.json')),'0114de28a20ec3b8d023b0fe786272d42f7b3b5e7ed95ff363b8638dc4e2a0b5');assert.equal(sum(await read('dist/apps/load-balance/1.8.5/manifest.json')),'df0707bc72114bae7571e23b6d6a8f430c583a2b5e8225d6fda99acf0601d915');
});
