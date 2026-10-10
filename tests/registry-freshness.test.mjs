import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {createHash} from 'node:crypto';
const read=path=>readFile(new URL('../'+path,import.meta.url),'utf8');
test('normal ADI signed frozen source includes pinned catalog reads, poll-safe receipts and bounded quota backoff',async()=>{
 const index=JSON.parse(await read('panel-integration/source-sha256.json')),release=JSON.parse(await read('panel-integration/release-source-inputs.json'));
 assert.equal(release.frozen_inputs_sha256,'0c09ccd8603afc68d42caed2a2f1c71672cded67d16e9ab888c9fc6dcc7e0fbb');
 assert.equal(release.archive_sha256,'203eddd7f66a7da29e21c3fce42cf56a7322c53ec519171c864199979d06a68c');
 assert.equal(Object.keys(index.files).length,999);
 for(const file of ['internal/appcatalog/catalog.go','internal/appcatalog/github_catalog.go','internal/appcatalog/github_catalog_test.go','internal/appcatalog/github_catalog_rate.go','internal/appcatalog/github_catalog_rate_test.go','scripts/test-registry-freshness.mjs','web/src/registryFreshness.ts','web/src/App.vue','packaging/build-release.sh']){
  const sha=createHash('sha256').update(await read('panel-integration/'+file)).digest('hex');assert.equal(release.files[file],sha,file);assert.equal(index.files[file],sha,file);
 }
 const gates=Object.keys(release.files).filter(f=>/^scripts\/test-[a-z0-9-]+\.mjs$/.test(f));assert.equal(gates.length,23);assert(gates.includes('scripts/test-registry-freshness.mjs'));
 const code=await read('panel-integration/internal/appcatalog/github_catalog.go');assert.match(code,/git\/ref\/heads\/main/);assert.match(code,/c\.BaseURL != DefaultBaseURL/);assert.match(code,/uniqueGitHubReference\(raw\)/);assert.match(code,/githubCatalogCommitBase\+commit\+"\/"\+relative/);
 const checks=await read('panel-integration/internal/appcatalog/github_catalog_test.go');for(const name of ['UsesResolvedImmutableCommitNotStaleMain','InvalidBranchMetadataNeverReadsMain','LegacyFallbackPinnedToSameCommit','FailuresKeepVerifiedCacheButNotFreshness','ClosedPathsAndCancellation','ConcurrentCacheRefreshes'])assert(checks.includes('TestOfficialCatalog'+name));
 const receipt=await read('panel-integration/web/src/registryFreshness.ts');assert.match(receipt,/ticket\.checkPending \|\| this\.pendingCheck/);assert.match(receipt,/ticket\.checkBarrier !== this\.checkBarrier/);assert.match(receipt,/source: \{ \.\.\.source, \.\.\.this\.failedSource, stale: true \}/);assert.match(receipt,/catalog !== this\.receiptCatalog/);
 const view=await read('panel-integration/web/src/App.vue');assert.match(view,/最近成功定位提交/);assert.match(view,/applyRegistryRead\(registryTicket, d\)/);assert.match(view,/registryFreshness\.reset\(\)/);assert.doesNotMatch(view,/appRegistry\.value = await api<AppRegistry>/);
 const gate=await read('panel-integration/scripts/test-registry-freshness.mjs');for(const phrase of ['actual receipt survives repeated cache polls','polls begun before or during an interactive check','failed real check remains stale and locked','newer check wins in either completion order','account reset discards old receipts','catalog identity changes clear the old commit'])assert(gate.includes(phrase));
 const rate=await read('panel-integration/internal/appcatalog/github_catalog_rate.go');assert.match(rate,/len\(values\) != 1/);assert.match(rate,/now\.Add\(24\s*\*\s*time\.Hour\)/);assert.match(rate,/result\.CheckedAt = retry\.checkedAt/);assert.match(rate,/result\.RetryAt = retry\.until/);
 assert.match(code,/c\.githubRefMu\.Lock\(\)/);assert.match(code,/fmt\.Errorf\("无法定位官方仓库当前提交: %w", err\)/);
 const retryTests=await read('panel-integration/internal/appcatalog/github_catalog_rate_test.go');for(const name of ['RetryHeadersBounded','RateCacheNeverClaimsFreshOrTouchesNetworkBeforeRetry','SecondaryBackoffIncreasesAndSuccessfulLookupResets','ConcurrentQuotaDoesNotBurstOrReadMutableMain','RetryDoesNotInventMetadataForCustomSource'])assert(retryTests.includes('TestGitHubCatalog'+name));
 assert.match(view,/到期后仍须重新检查/);assert(gate.includes('server retry deadlines stay failure evidence'));
 const contracts=JSON.parse(await read('registry/functional-contracts.json'));assert.equal(contracts.commercial_feature_parity_complete,false);assert.equal(contracts.catalog_delivery.reviewed_panel_release,'0.1.0-dev.proapps24loadexportyu');assert(contracts.catalog_delivery.retry_boundaries.some(s=>s.includes('进程内')));
 const lb=contracts.apps.find(a=>a.id==='load-balance');assert(lb.boundaries.some(s=>s.includes('下载事件超时')));assert(lb.scenarios.some(s=>s.includes('1.8.0 到 1.8.1')&&s.includes('2 份归档')));
 const registry=JSON.parse(await read('registry/apps.json'));assert.equal(registry.apps.length,50);assert.equal(registry.apps.find(a=>a.id==='load-balance').version,'1.8.2');
});
