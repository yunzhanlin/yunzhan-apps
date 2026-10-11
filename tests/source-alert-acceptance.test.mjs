import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {createHash} from 'node:crypto';
const read=p=>readFile(new URL('../'+p,import.meta.url),'utf8');
const sha=s=>createHash('sha256').update(s).digest('hex');

test('actual source acceptance proof cohorts stay distinct from prior failures, Main program delivery and incomplete commercial work',async()=>{
 const c=JSON.parse(await read('registry/functional-contracts.json')),r=c.reviewed_normal_release,a=r.installed_load_balance_source_acceptance;
 assert.equal(c.commercial_feature_parity_complete,false);assert.equal(r.all_50_commercial,false);
 assert.equal(r.release,'0.1.0-dev.proapps24inventorybefm');assert.equal(r.actual_normal_executor_companion_passes,637);assert.equal(r.actual_normal_executor_companion_failures,0);
 assert.equal(r.actual_github_pr_linux_ci.head,'645b8b7cd067109e8739d43884b7fae4fd9935e4');assert.equal(r.actual_github_pr_linux_ci.run,38184308292);
 assert.equal(r.actual_github_main_linux_ci.head,'1bafa42ed153e4d17ca3455e57579b9ef2155f00');assert.equal(r.actual_github_main_linux_ci.run,38184697117);
 for(const ci of [r.actual_github_pr_linux_ci,r.actual_github_main_linux_ci]){assert.equal(ci.passed,true);assert.equal(ci.targeted_reader_race_passed,true);assert.match(ci.log_sha256,/^[a-f0-9]{64}$/);}
 assert.equal(c.previous_gateway_release.actual_first_github_pr_ci_passed,false);assert.equal(c.previous_gateway_release.actual_first_github_pr_ci_run,38182561913);
 assert.equal(c.previous_source_release.actual_signed_upgrade_verification_passed,false);assert.equal(c.previous_source_release.immediate_failed_upgrade_full_baseline_saved,false);
 assert.equal(a.version,'1.8.5');assert.equal(a.catalog_sha256,sha(await read('dist/catalog-v1.json')));assert.equal(a.manifest_sha256,sha(await read('dist/apps/load-balance/1.8.5/manifest.json')));
 assert.equal(a.actual_signed_update_proof_sha256,'247ef697892c585571184dbe983474948fba4f0d311b01d61293df75fa778ee5');assert.equal(a.actual_signed_update_checks,43);assert.equal(a.actual_update_ui_posts,1);assert.equal(a.controlled_same_identity_replays,1);
 assert.equal(a.actual_update_job_id,'a916f2837ec3dc0a3c480f88d4422759');assert.equal(a.actual_update_request_identity,'5f16a2ee-0c53-41f4-a0de-79ddcad1636b');
 assert.equal(a.actual_business_proof_sha256,'56c4c829656948829db6db53e6fab374e20d82ce78478760b5525c7e56c14ffa');assert.equal(a.actual_business_checks,5);assert.equal(a.source_delivery_requests,4);assert.equal(a.health_delivery_requests,1);assert.equal(a.traffic_delivery_requests,5);
 assert.equal(a.actual_source_fault_retry_restart_pause_verified,true);assert.equal(a.actual_source_history_summary_verified,true);assert.equal(a.actual_recovered_and_pending_transaction_interruption_verified,false);
 assert.equal(a.retained_first_browser_failure.passed,false);assert.equal(a.retained_first_browser_failure.checks,30);assert.equal(a.retained_first_browser_failure.channel_puts,1);
 assert.equal(a.retained_first_browser_failure.proof_sha256,'31212183d754d626326dfdb733687e99ee0a2c645f1b792a0a3ea96e4b2ee602');
 assert.equal(a.actual_readonly_browser_continuation_proof_sha256,'d79a4c41f9ba6011a82f20e927b23de8637af3689197379e36a5f29be43cc0a5');assert.equal(a.actual_readonly_browser_continuation_checks,53);assert.equal(a.additional_channel_puts,0);assert.equal(a.original_saved_request_preservation_verified,true);
 assert.match(a.scope,/SSH Origin adapter/);assert.match(a.scope,/no Main LB installation/);assert.match(a.scope,/power loss/);
 assert.equal(r.main_release_delivered,true);assert.equal(r.actual_main_program_delivery_proof_sha256,'451a394274293b50d28f4a1f99cf791d02e5752642f3d308a33b5e91db350c2b');assert.equal(r.actual_main_program_delivery_checks,10);
 assert.equal(r.original_main_site_count,58);assert.equal(r.original_main_website_source_files,4098);assert.equal(r.original_main_sql_tables_compared,18);assert.equal(r.original_main_installed_app_count,12);assert.equal(r.main_auto_installed_new_apps,0);
 assert.equal(r.actual_main_direct_origin_browser_proof_sha256,'a420f3c3984f4035c803ea324c1d522ddc3ef6a519773029aeaa6fbf44636d95');assert.equal(r.actual_main_direct_origin_browser_checks,44);assert.equal(r.actual_main_source_observation_rows,0);assert.equal(r.actual_main_implicit_source_notices,0);
 const w=r.actual_main_waf_stable_capture;assert.equal(w.passed,true);assert.equal(w.checks,12);assert.equal(w.proof_sha256,'5a265672ab460651da1c5abc7ce6776237ed245de3cfa2918c763c880b680d8b');assert.equal(w.application_write_requests,0);assert.equal(w.original_main_ui_loading_frame_retained,true);assert.equal(w.retained_wrong_heading_fixture_failure_sha256,'3e2a7d0855abe379c545f5fe835d5c7be499b6fc2395da27d64072106f064a3f');
 assert.match(r.real_qa_scope,/Generic production installer queues\/rollback\/failure injection/);assert.match(r.real_qa_scope,/all50 commercial remain incomplete/);
 const lb=c.apps.find(a=>a.id==='load-balance');assert(lb.gaps.some(s=>s.includes('温缓存')&&s.includes('仍待完成')));assert(lb.gaps.some(s=>s.includes('实际pending/recovered中断')&&s.includes('仍待完成')));assert(lb.boundaries.some(s=>s.includes('通用生产installer')&&s.includes('仍待修复')));
});
