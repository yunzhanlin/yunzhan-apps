import{originalReviewedHTTPSFixtureWorkflow}from'./reviewed-https-fixture-workflow.mjs';
import test from 'node:test';import assert from 'node:assert/strict';import fs from 'node:fs';
import path from 'node:path';import {fileURLToPath} from 'node:url';import {createHash} from 'node:crypto';
import {originalAnalyticsWorkflow} from './pre-analytics-workflow.mjs';
import {catalogBeforeAnalyticsBytes} from './previous-analytics-catalog.mjs';
const root=fileURLToPath(new URL('../',import.meta.url)),read=p=>fs.readFileSync(path.join(root,p)),json=p=>JSON.parse(read(p)),sha=b=>createHash('sha256').update(b).digest('hex');
test('session maintenance is exact newly signed immutable source, not a rewrite of the prior source or application',()=>{
 const i=json('panel-integration-analytics-session/source-sha256.json'),f=json('panel-integration-analytics-session/release-source-inputs.json'),r=json('registry/analytics-session-core-release.json'),old=json('panel-integration-file-manager/source-sha256.json');
 assert.equal(r.frozen_inputs_sha256,'221086c5c2d28f752a1f51d8f9bb0433c33eddc841e63297eef9cfb373ad2bf7');assert.equal(r.version,'0.1.0-dev.proapps24analyticsessionbgnm');
 assert.equal(i.release.frozen_inputs_sha256,r.frozen_inputs_sha256);assert.equal(f.frozen_inputs_sha256,r.frozen_inputs_sha256);assert.equal(f.archive_sha256,r.normal_original_key_archives.amd64);assert.deepEqual(i.files,f.files);assert.deepEqual(i.test_overrides,{});assert.equal(Object.keys(i.files).length,1508);
 for(const [p,digest]of Object.entries(i.files)){assert.equal(sha(read('panel-integration-analytics-session/'+p)),digest,p);assert(!p.split('/').some(s=>['node_modules','.local','.git'].includes(s)),p);}
 const delta=[...new Set([...Object.keys(i.files),...Object.keys(old.files)])].filter(p=>i.files[p]!==old.files[p]).sort();assert.deepEqual(delta,r.exact_source_delta);assert.equal(delta.length,15);
 assert.equal(r.new_app_manifest_published,false);assert.equal(r.new_signed_application_updated,false);assert.equal(r.commercial_all50,false);assert.equal(r.QA_programs_upgraded_to_this_source,false);
 assert.equal(sha(catalogBeforeAnalyticsBytes()),r.current_catalog_sha256_unchanged);assert.equal(sha(read('dist/apps/website-analytics/2.3.0/manifest.json')),'4953ee9526b5e5b189f59eed5731d2ca40f3b76c715319e215b0f3fe3a9f1ec8');
});
test('actual elapsed-time browser and signed Main program proofs remain distinct from source fixtures and app installation',()=>{
 const r=json('registry/analytics-session-core-release.json');
 assert.equal(r.local_go.passed,2580);assert.equal(r.local_go.failed,0);assert.equal(r.local_go.explicit_skips,12);
 for(const a of ['arm64','amd64']){const n=r.Root_Linux_source_fixtures[a];assert.equal(n.core.passed,56);assert.equal(n.catalog.passed,14);assert.equal(n.executor.passed,57);assert.equal(n.core.explicit_skips.length,2);assert.equal(n.executor.explicit_skips.length,8);assert.equal(n.complete_original_business_projections_preserved,101);assert.equal(n.installed_program_or_module_changed,false);}
 const b=r.real_browser_source;assert(b.passed&&b.wall_idle_seconds>=1805&&b.actual_received_gap_seconds>=1800&&b.original_visitor_preserved&&b.new_session_and_page);assert.equal(b.browser_clock_or_storage_overridden,false);assert.equal(b.signed_installed_collector_acceptance,false);
 const m=r.actual_Main_program_delivery;assert(m.ok&&m.normal_original_key_signed_installer&&m.nginx_process_unchanged&&m.actual_existing_account_browser_login);assert.equal(m.preflight_exit,0);assert.equal(m.install_exit,0);assert.equal(m.original_business_projections,101);assert.equal(m.schema_or_migration_rows_changed,false);assert.equal(m.sites,58);assert.equal(m.modules,4);assert.equal(m.non_program_protected_entries,43010);assert.equal(m.HTTP19100,200);assert.equal(m.HTTP19101,200);
 assert(r.original_failed_executor_fixture_retained);assert.equal(r.original_failed_fixture_relabelled,false);assert.equal(r.physical_mobile_acceptance,false);assert.equal(r.actual_power_loss_acceptance,false);
});
test('all earlier workflow bytes stay intact before appended new-source positive handler and actual tracker gates',()=>{
 const workflow=originalAnalyticsWorkflow(originalReviewedHTTPSFixtureWorkflow(read('.github/workflows/verify.yml'))).toString(),marker='      - name: Analytics session complete Root Linux contracts (source only)',at=workflow.indexOf(marker);assert(at>0);
 const original=workflow.slice(0,at);assert.equal(sha(Buffer.from(original)),'fd925cd2e8aa81fb871077615778ee79decbae65942b9cec7412a79f3886eb63');assert(original.includes('working-directory: panel-integration-file-manager'));assert(original.includes("test_program_queue_diagnostics test_production_upgrade test_development_upgrade_safety test_install_development_dispatch test_install_dependency_policy test_install_gateway_policy"));
 const current=workflow.slice(at);for(const s of ['working-directory: panel-integration-analytics-session','sudo "$(command -v go)" test -p 1 ./... -count=1','TestPublishedRepositoryCurrentSignedManifestABI','scripts/test-analytics-session.mjs','scripts/test-analytics-html-state.mjs','scripts/test-analytics-tracker.mjs','scripts/web-entry-budget.mjs'])assert(current.includes(s),s);
});
