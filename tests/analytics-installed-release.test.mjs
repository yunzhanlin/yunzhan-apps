import test from 'node:test';import assert from 'node:assert/strict';import fs from 'node:fs';import {createHash,createPublicKey,verify} from 'node:crypto';
const read=p=>fs.readFileSync(new URL('../'+p,import.meta.url)),json=p=>JSON.parse(read(p)),sha=b=>createHash('sha256').update(b).digest('hex');
test('completed actual19100 update has a new receipt without rewriting historical signing boundaries',()=>{
 const r=json('registry/analytics-2.3.1-installed-release.json'),old=json(r.historical_at_signing_record_preserved),m=r.Main19100_actual_store;
 assert.equal(old.at_signing_Main_application_update_proven,false);assert.equal(old.at_signing_GitHub_publication_proven,false);
 assert.equal(r.published_commit,'68784c77aa7b872cb310a386faba1a5aeafc7086');assert.equal(r.published_pull_request,53);assert(r.immutable_remote_GitHub_bytes_match_original_signed_bytes&&r.original_Ed25519_public_trust_verified);
 assert.equal(m.normal_original_update_submissions,1);assert.equal(m.original_job_kind,'software_update');assert.equal(m.original_job_state,'succeeded');assert.equal(m.installed_version_after,'2.3.1');assert.equal(m.new_version_count_after,0);assert(m.update_button_removed);assert.equal(m.sites_preserved,58);assert.equal(m.installed_module_count_preserved,4);assert.equal(m.protected_entries,43186);assert.equal(m.complete_original_projection_sets_qualified,100);assert(m.receipt_boundary.includes('not claimed or reconstructed'));
 assert.equal(m.program_or_Nginx_master_changed_by_app_update,false);assert.equal(m.automatically_enabled_collection_or_HTML_engine,false);assert.equal(r.installed_collector_end_to_end_browser_journey_proven,false);assert.equal(r.all50_commercial,false);
});
test('actual-update receipt pins the unchanged original Ed25519 catalog and immutable2.3.1 package',()=>{
 const r=json('registry/analytics-2.3.1-installed-release.json'),catalog=read('dist/catalog-v1.json'),pub=read('signatures/catalog-v1.pub.pem');
 assert.equal(sha(catalog),r.catalog_sha256);assert.equal(sha(pub),r.public_key_sha256);assert(verify(null,catalog,createPublicKey(pub),Buffer.from(read('signatures/catalog-v1.sig').toString().trim(),'base64')));
 const item=JSON.parse(catalog).apps.find(v=>v.id===r.application);assert.equal(item.version,r.version);assert.equal(item.sha256,r.manifest_sha256);assert.equal(sha(read('dist/apps/website-analytics/2.3.1/manifest.json')),r.manifest_sha256);
});
