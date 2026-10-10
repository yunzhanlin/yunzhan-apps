import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {createHash} from 'node:crypto';
const read=path=>readFile(new URL('../'+path,import.meta.url),'utf8');
test('normal XV signed frozen source includes commit-pinned catalog reads and poll-safe freshness receipts',async()=>{
 const index=JSON.parse(await read('panel-integration/source-sha256.json')),release=JSON.parse(await read('panel-integration/release-source-inputs.json'));
 assert.equal(release.frozen_inputs_sha256,'8ad35fbbcd756e6918b0117a6f5bd590c47067cb6ca83cafdffafb1ee0955e80');
 assert.equal(release.archive_sha256,'b0704141e2a6f9a2a7b02a2ac3a9385e3fd424e742a01a22ddee2d3256f71690');
 assert.equal(Object.keys(index.files).length,978);
 for(const file of ['internal/appcatalog/catalog.go','internal/appcatalog/github_catalog.go','internal/appcatalog/github_catalog_test.go','scripts/test-registry-freshness.mjs','web/src/registryFreshness.ts','web/src/App.vue','packaging/build-release.sh']){
  const sha=createHash('sha256').update(await read('panel-integration/'+file)).digest('hex');assert.equal(release.files[file],sha,file);assert.equal(index.files[file],sha,file);
 }
 const gates=Object.keys(release.files).filter(f=>/^scripts\/test-[a-z0-9-]+\.mjs$/.test(f));assert.equal(gates.length,19);assert(gates.includes('scripts/test-registry-freshness.mjs'));
 const code=await read('panel-integration/internal/appcatalog/github_catalog.go');assert.match(code,/git\/ref\/heads\/main/);assert.match(code,/c\.BaseURL != DefaultBaseURL/);assert.match(code,/uniqueGitHubReference\(raw\)/);assert.match(code,/githubCatalogCommitBase\+commit\+"\/"\+relative/);
 const checks=await read('panel-integration/internal/appcatalog/github_catalog_test.go');for(const name of ['UsesResolvedImmutableCommitNotStaleMain','InvalidBranchMetadataNeverReadsMain','LegacyFallbackPinnedToSameCommit','FailuresKeepVerifiedCacheButNotFreshness','ClosedPathsAndCancellation','ConcurrentCacheRefreshes'])assert(checks.includes('TestOfficialCatalog'+name));
 const receipt=await read('panel-integration/web/src/registryFreshness.ts');assert.match(receipt,/ticket\.checkPending \|\| this\.pendingCheck/);assert.match(receipt,/ticket\.checkBarrier !== this\.checkBarrier/);assert.match(receipt,/source: \{ \.\.\.source, \.\.\.this\.failedSource, stale: true \}/);assert.match(receipt,/catalog !== this\.receiptCatalog/);
 const view=await read('panel-integration/web/src/App.vue');assert.match(view,/最近成功定位提交/);assert.match(view,/applyRegistryRead\(registryTicket, d\)/);assert.match(view,/registryFreshness\.reset\(\)/);assert.doesNotMatch(view,/appRegistry\.value = await api<AppRegistry>/);
 const gate=await read('panel-integration/scripts/test-registry-freshness.mjs');for(const phrase of ['actual receipt survives repeated cache polls','polls begun before or during an interactive check','failed real check remains stale and locked','newer check wins in either completion order','account reset discards old receipts','catalog identity changes clear the old commit'])assert(gate.includes(phrase));
 const contracts=JSON.parse(await read('registry/functional-contracts.json'));assert.equal(contracts.commercial_feature_parity_complete,false);assert.equal(contracts.catalog_delivery.reviewed_panel_release,'0.1.0-dev.proapps24registryorderxv');
 const lb=contracts.apps.find(a=>a.id==='load-balance');assert(lb.gaps.some(s=>s.includes('下载事件超时')));assert(lb.scenarios.some(s=>s.includes('1.8.0 到 1.8.1')&&s.includes('2 份归档')));
 const registry=JSON.parse(await read('registry/apps.json'));assert.equal(registry.apps.length,50);assert.equal(registry.apps.find(a=>a.id==='load-balance').version,'1.8.1');
});
