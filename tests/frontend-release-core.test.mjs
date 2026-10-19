import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {createHash} from 'node:crypto';
const root=fileURLToPath(new URL('../',import.meta.url)),read=p=>fs.readFileSync(path.join(root,p));
const json=p=>JSON.parse(read(p)),sha=b=>createHash('sha256').update(b).digest('hex');
const r=json('registry/frontend-release-core.json'),scope='panel-integration-ui-release/';
test('new immutable frontend scope binds all 1528 normal archive input bytes and preserves every runtime input',()=>{
 const index=json(scope+'source-sha256.json'),release=json(scope+'release-source-inputs.json'),old=json('panel-integration-statistics-stop/source-sha256.json');
 assert.equal(r.frozen_inputs_sha256,'ce24c87e8583dc7412c7b3cd3d48745feeafe5773627549bd7df47d66cb05fb7');
 assert.equal(r.version,'0.1.0-dev.proapps24pkglabelbgzc');assert.equal(r.frozen_files,17171);assert.equal(r.exported_files,1528);assert.equal(r.source_overrides,0);
 assert.equal(index.release.frozen_inputs_sha256,r.frozen_inputs_sha256);assert.equal(index.release.archive_sha256,r.normal_archives.amd64.archive_sha256);assert.deepEqual(index.files,release.files);assert.deepEqual(index.test_overrides,{});
 assert.equal(Object.keys(index.files).length,1528);assert.equal(Object.keys(old.files).length,1525);assert.equal(old.release.frozen_inputs_sha256,'73d37ae9b8ddecbb02d9d2c1adf1995b997ac60d25f32b4f43f551caefada078');
 const changed=Object.keys(index.files).filter(p=>index.files[p]!==old.files[p]).sort();
 assert.deepEqual(changed,['packaging/build-release.sh','scripts/test-disk-scan-lifecycle.mjs','scripts/test-frontend-release.mjs','scripts/test-store-updates.mjs','web/src/App.vue','web/src/frontendRelease.ts','web/src/registryVersionLabel.ts']);
 assert(Object.keys(old.files).every(p=>p in index.files));
 for(const[p,digest]of Object.entries(index.files)){assert(!p.split('/').some(x=>['.local','.git','node_modules','..'].includes(x)));assert.equal(sha(read(scope+p)),digest,p);if(!changed.includes(p))assert.equal(digest,old.files[p],p);}
 const native=r.retained_native_runtime_evidence;assert(native.Go_Python_installers_and_runtime_assets_byte_identical&&native.new_frontend_not_relabelled_as_native_fixture_or_business_coverage);assert.equal(native.source_inputs_sha256,old.release.frozen_inputs_sha256);
});
test('both original-key normal QA deliveries and Main retain data and unchanged program trust roots',()=>{
 assert.equal(r.original_signer_sha256,'fe128e82b4e11345b320cd782134768bfe1a4df14947c425d7494873a7a7b7b5');assert.equal(r.original_public_key_sha256,'4ccfcc861d56a41e3ba7f7ace7e2432c815f366c58448d783df92c6632f01339');
 for(const arch of ['arm64','amd64']){const a=r.normal_archives[arch],q=r.normal_QA_upgrades[arch];for(const key of ['archive_sha256','manifest_sha256','signature_sha256','complete_normal_build_log_sha256'])assert.match(a[key],/^[a-f0-9]{64}$/);assert(a.signature_verified&&q.normal_original_key_installer&&q.statistics_history_preserved&&q.complete_observation_identity_preserved&&q.no_live_history_recovery);assert.equal(q.preflight_exit,0);assert.equal(q.install_exit,0);assert.equal(q.core_projections_preserved,101);assert.equal(q.app_operations,0);}
 const m=r.Main19100_delivery;assert.equal(m.preflight_exit,0);assert.equal(m.install_exit,0);assert(m.complete_101_schema_migrations_and_business_preserved&&m.nginx_process_preserved&&m.no_app_operations&&m.website_probe_after_exact_preservation);assert.equal(m.sites_preserved,58);assert.equal(m.app_records_preserved,4);assert.equal(m.analytics_version,'2.3.1');assert.equal(m.protected_other_files,43022);assert.equal(m.ready_http,200);assert.equal(m.website_http,200);
});
test('real ARM old-tab write refusal and explicit reload never claim a second AMD journey or all50',()=>{
 const p=r.real_ARM_browser_transition;assert(p.actual_old_UI_stop_blocked&&p.no_new_native_job_or_receipt_overwrite&&p.same_original_container_identity_and_HTTP200&&p.explicit_notice_button_reload&&p.raw_watcher_source_identical);assert.equal(p.old_entry,'./assets/index-C4ZRdQPc.js');assert.equal(p.new_entry,'./assets/index-Cvl9QUkY.js');assert.equal(r.Main19100_delivery.same_signed_new_frontend_entry,p.new_entry);assert.equal(p.AMD_same_browser_transition_executed,false);assert.equal(r.commercial_all50,false);assert(r.limitations.some(s=>s.includes('WebSockets'))&&r.limitations.some(s=>s.includes('PHP and IDS')));
});
test('new frontend CI appends to the complete old workflow without weakening original gates',()=>{
 const c=read('.github/workflows/verify.yml').toString(),at=c.indexOf('\n  frontend-release-native-amd64:\n');assert(at>0);assert.equal(sha(Buffer.from(c.slice(0,at))),r.prior_workflow_whole_sha256);assert.equal(r.prior_workflow_whole_sha256,'56cbca761cba10b72822757a7995b28e9e3a2402401bb3530e518f0629cab842');assert.doesNotMatch(c,/continue-on-error/);assert.equal(r.mandatory_additional_CI_job,'frontend-release-native-amd64');
 for(const s of ['runs-on: ubuntu-24.04','scripts/test-frontend-release.mjs','scripts/test-store-updates.mjs','scripts/test-disk-scan-lifecycle.mjs','scripts/test-docker-site-binding.mjs','npm ci --prefix panel-integration-ui-release/web --ignore-scripts','npm run build --prefix web','scripts/web-entry-budget.mjs web/dist'])assert(c.slice(at).includes(s),s);
 assert(read(scope+'packaging/build-release.sh').toString().includes('scripts/test-frontend-release.mjs'));
});
