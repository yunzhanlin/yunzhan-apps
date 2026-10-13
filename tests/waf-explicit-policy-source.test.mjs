import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile}from'node:fs/promises';
import {createHash}from'node:crypto';
const read=p=>readFile(new URL('../'+p,import.meta.url),'utf8');
const sha=s=>createHash('sha256').update(s).digest('hex');
test('two-file WAF fix is pinned to a new real signed release, not rewritten historical BESO source',async()=>{
 const current=JSON.parse(await read('panel-integration-geography/source-sha256.json')),old=JSON.parse(await read('registry/reviewed-sources/0.1.0-dev.proapps24statsboundedbeso/source-sha256.json'));
 const oldBuild=JSON.parse(await read('registry/reviewed-sources/0.1.0-dev.proapps24statsboundedbeso/release-source-inputs.json'));
 assert.equal(old.release.frozen_inputs_sha256,'261a5b89d1288ae85c5b3a3160f8e886bc20319cfcf4202c5bb8242cd9182dd0');assert.equal(old.release.archive_sha256,'84ffbf8cbd8c39d89c64eeb7cb93abdfc2c779654091fb2e86eac05f1737d9a7');
 assert.deepEqual(Object.keys(current.files),Object.keys(old.files));assert.deepEqual(current.test_overrides??{},{});assert.deepEqual(old.test_overrides??{},{});
 const changes=Object.keys(current.files).filter(p=>current.files[p]!==old.files[p]);assert.deepEqual(changes,['internal/core/software_apps.go','internal/core/software_apps_test.go']);
 for(const [p,digest]of Object.entries(oldBuild.files))assert.equal(old.files[p],digest,p);
 const code=await read('panel-integration-geography/internal/core/software_apps.go');assert(code.includes('field != "profile" && field != "rate_per_second"'));assert(code.includes('未保存或忽略部分配置'));
 const fixture=await read('panel-integration-geography/internal/core/software_apps_test.go');assert(fixture.includes('TestWAFLegacySettingsNeverSilentlyDiscardAdvancedPolicyFields'));assert(fixture.includes('jobs != 0 || audits != 0'));
 const record=JSON.parse(await read('registry/waf-explicit-policy-release.json'));assert.equal(record.frozen_inputs_sha256,current.release.frozen_inputs_sha256);assert.deepEqual(record.only_source_changes,changes);assert.equal(record.main_delivered,false);assert.equal(record.commercial_all50,false);assert.equal(record.actual_complete_policy_forwarder_integration.synthetic_forwarded_ips,true);
 assert.equal(sha(await read('dist/apps/website-statistics-v2/2.6.0/manifest.json')),'17d8a5fb7f48a2e448103580c77067b249281d413f3182c3f7d1e2291ac54d70');
});
