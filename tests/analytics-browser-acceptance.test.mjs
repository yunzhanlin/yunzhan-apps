import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
const json=p=>JSON.parse(fs.readFileSync(new URL('../'+p,import.meta.url)));
test('actual installed analytics browser receipt keeps the original19100 signing/update boundaries immutable',()=>{
 const r=json('registry/analytics-2.3.1-browser-acceptance.json'),original=json(r.original_Main19100_update_record_preserved);
 assert.equal(r.application,'website-analytics');assert.equal(r.version,'2.3.1');assert(r.original_Main19100_update_not_replayed);
 assert.equal(original.Main19100_actual_store.update_job,'f205ba180076fd2069f164efd019b784');
 assert.equal(original.installed_collector_end_to_end_browser_journey_proven,false);
 assert.equal(r.QA_core_source_inputs_sha256,'86f0c4792f7e0b81955d568179147dfe746949d0aaa06f2dea976b842663e8b2');
 assert.equal(r.QA_original_app_update_job,'c0eebafa04ac3c1a9c122ca740f74290');assert.equal(r.QA_original_app_update_state,'succeeded');
 assert.equal(r.automatic_HTML_engine_acceptance,false);assert.equal(r.Main19100_browser_journey_acceptance,false);assert.equal(r.all50_commercial,false);
});
test('natural idle and original normal proxy tasks have scoped non-synthetic and preservation evidence',()=>{
 const r=json('registry/analytics-2.3.1-browser-acceptance.json'),b=r.browser_journey,p=r.normal_site_proxy_tasks;
 assert(b.natural_idle_seconds>=1800&&b.last_original_event_to_return_seconds>=1800);assert.deepEqual([b.pv,b.browser_uv,b.sessions],[2,1,2]);
 assert(b.same_visitor_new_session_after_real_idle);assert.equal(b.original_events_preserved,8);assert.equal(b.original_page_hashes_preserved,4);assert.equal(b.original_program_identities_preserved,3);assert.equal(b.standard_INP_ms,336);assert.equal(b.performance_events_with_measured_INP,3);
 assert.equal(b.private_input_or_click_coordinates_collected,false);assert.equal(b.browser_clock_storage_or_database_events_modified,false);
 assert(p.both_original_jobs_succeeded&&p.nginx_test_reload_and_real_HTTP200_proven&&p.site_nginx_bytes_restored_exactly_on_disable);
 assert(p.all20_installed_app_records_equal_between_enable_and_disable&&p.Apache_three_files_process_version_and_loaded_fingerprint_preserved&&p.retention_click_privacy_and_original_public_key_preserved);
 assert.equal(p.historical_events_retained_after_disable,13);assert.equal(p.original_failed_configuration_job,'3b57955be15be3f71a2f61c353c2af11');assert(p.original_failed_configuration_job_still_failed);
 for(const value of [b.qualified_receipt_sha256,p.qualified_receipt_sha256,...Object.values(b.original_snapshot_sha256)])assert.match(value,/^[a-f0-9]{64}$/);
 assert.equal(r.collector_integration,'Original manual tags, automatically managed same-origin per-site proxy; no page/template edits during this acceptance.');
});
