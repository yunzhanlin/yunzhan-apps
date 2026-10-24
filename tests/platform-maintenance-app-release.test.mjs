import{originalReviewedHTTPSFixtureWorkflow}from'./reviewed-https-fixture-workflow.mjs';
import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {createHash} from 'node:crypto';
import {validateManifest} from '../tools/lib.mjs';
import {catalogBeforeMaintenance130} from './previous-maintenance-catalog.mjs';
import {catalogBeforeDisk130,catalogBeforeDisk130Bytes} from './previous-disk-catalog.mjs';
const read=p=>readFile(new URL('../'+p,import.meta.url),'utf8');
const sha=b=>createHash('sha256').update(b).digest('hex');
test('independent1.3 installable package changes exactly one app and retains original publisher, signed catalog and immutable1.2 bytes',async()=>{
 const catalog=await catalogBeforeDisk130(JSON.parse(await read('dist/catalog-v1.json')));
 const old=await catalogBeforeMaintenance130(catalog);
 assert.deepEqual(catalog.apps.filter(a=>a.id!=='platform-ops'),old.apps.filter(a=>a.id!=='platform-ops'));
 const raw=await read('dist/apps/platform-ops/1.3.0/manifest.json'),m=JSON.parse(raw);
 assert.deepEqual(validateManifest(m),[]);assert.equal(m.id,'platform-ops');assert.equal(m.version,'1.3.0');assert.equal(m.stage,'ready');
 assert.deepEqual(m.required_panel_features,['platform-maintenance-v1']);assert.match(m.summary,/可安装验收版/);assert.match(m.summary,/商用能力仍在验收/);
 assert.equal(m.delivery.provider,'panel-module');assert.equal(m.delivery.target,'platform-ops');
 assert.equal(sha(raw),'6d433842fb11880283548bcc739d47b17c46c3d3d7242fefa1494faf9da0b346');
 assert.equal(sha(await read('dist/apps/platform-ops/1.2.0/manifest.json')),'2962907ca319b6266c369df203f46886609073651b2aa7f6baa316a95b885de9');
 const r=JSON.parse(await read('registry/platform-maintenance-app-release.json'));
 assert.equal(r.manifest_sha256,sha(raw));assert.equal(r.catalog_sha256,sha(await catalogBeforeDisk130Bytes(catalog)));
 for(const key of ['commercial_all50','platform_ops_commercial','main_program_delivered','installed_app_update_verified_at_publication','publisher_key_changed'])assert.equal(r[key],false,key);
 assert.equal(r.retained_ci_failure.original_failure_rewritten,false);
 const ci=originalReviewedHTTPSFixtureWorkflow(await read('.github/workflows/verify.yml'));
 const install=ci.indexOf('npm ci --prefix panel-integration-geography/web --ignore-scripts');
 assert(install>=0&&install<ci.indexOf('node --test panel-integration-geography/scripts/test-deferred-workspace.mjs'));
});
test('maintenance publication cannot forge historical other49 scope by changing an old expected digest',async()=>{
 const catalog=JSON.parse(await read('dist/catalog-v1.json'));
 for(const change of [c=>{c.apps.find(a=>a.id==='redis').summary+=' altered';},c=>{c.apps.find(a=>a.id==='platform-ops').sha256='0'.repeat(64);},c=>{c.generated_at='2026-10-01T00:00:00Z';}]){
  const bad=structuredClone(catalog);change(bad);await assert.rejects(()=>catalogBeforeMaintenance130(bad));
 }
});
