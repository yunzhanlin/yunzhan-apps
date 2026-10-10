import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {createHash} from 'node:crypto';
const read=p=>readFile(new URL('../'+p,import.meta.url),'utf8');
test('ADI exports the exact signed recovery, session, Git transport and unchanged byte-budget inputs',async()=>{
 const release=JSON.parse(await read('panel-integration/release-source-inputs.json')),index=JSON.parse(await read('panel-integration/source-sha256.json'));
 assert.equal(release.frozen_inputs_sha256,'0c09ccd8603afc68d42caed2a2f1c71672cded67d16e9ab888c9fc6dcc7e0fbb');
 assert.equal(release.archive_sha256,'203eddd7f66a7da29e21c3fce42cf56a7322c53ec519171c864199979d06a68c');
 assert.equal(Object.keys(index.files).length,999);
 for(const file of ['internal/appcatalog/github_catalog_git.go','internal/appcatalog/github_catalog_git_test.go','web/src/deferredWorkspace.ts','web/src/menuPermissions.ts','web/src/App.vue','scripts/test-deferred-workspace.mjs','web/src/moduleInitialInspection.ts','web/src/AppModuleManager.vue','scripts/test-web-entry-budget.mjs','scripts/web-entry-budget.mjs','packaging/build-release.sh']){
  const digest=createHash('sha256').update(await read('panel-integration/'+file)).digest('hex');assert.equal(release.files[file],digest,file);assert.equal(index.files[file],digest,file);
 }
 const gates=Object.keys(release.files).filter(f=>/^scripts\/test-[a-z0-9-]+\.mjs$/.test(f));assert.equal(gates.length,23);
 const build=await read('panel-integration/packaging/build-release.sh');for(const gate of ['test-deferred-workspace.mjs','test-web-entry-budget.mjs','web-entry-budget.mjs'])assert(build.includes(gate));
 const deferred=await read('panel-integration/web/src/deferredWorkspace.ts');assert.match(deferred,/if \(this.codeFailure\) throw this.codeFailure/);assert.match(deferred,/return this.current\(ticket\) \? value : undefined/);assert.equal((deferred.match(/if \(!current\(\)\) throw expiredWorkspace\(\)/g)||[]).length,4);assert.match(deferred,/message.slice\(0, 512\)/);
 const view=await read('panel-integration/web/src/App.vue');assert.match(view,/window.location.reload\(\)/);assert.match(view,/cause instanceof WorkspaceCodeLoadError/);assert.match(view,/epoch === accessEpoch && session === csrf.value/);assert.match(view,/canOpenAppModule\(accessPlan.value, id\)/);
 const fixtures=await read('panel-integration/scripts/test-deferred-workspace.mjs');assert.equal((fixtures.match(/^test\(/gm)||[]).length,18);assert(fixtures.includes('never replayed'));assert(fixtures.includes('changing accounts'));
 const budget=await read('panel-integration/scripts/web-entry-budget.mjs');assert.match(budget,/const limit=1_200_000/);assert.match(budget,/constants.O_NOFOLLOW/);assert.match(budget,/visited.size>=64/);assert.match(budget,/total>limit/);assert.match(budget,/Application manager is still eagerly loaded/);assert.match(budget,/all.length>128/);assert.match(budget,/deferred.length!==1/);
 assert.equal((await read('panel-integration/scripts/test-web-entry-budget.mjs')).match(/^test\(/gm).length,12);
});
test('current signed manager opens Apache read-only and never inspects a partially loaded page',async()=>{
 const selector=await read('panel-integration/web/src/moduleInitialInspection.ts'),manager=await read('panel-integration/web/src/AppModuleManager.vue');
 assert.match(selector,/loadSucceeded !== true \|\| installed !== true/);
 assert.match(selector,/d.id !== id/);assert.match(selector,/if \(id === "apache-waf"\) return/);
 assert.match(selector,/if \(id === "nfs-manager"\) return d.actions.includes\("server-report"\)/);
 assert.match(selector,/d.actions.includes\("policies"\)/);assert.match(selector,/id !== "platform-ops"/);
 const show=manager.slice(manager.indexOf('async function show('),manager.indexOf('function selected('));
 assert.match(show,/let pageReady = false/);assert.match(show,/initialModuleInspection\(id, definition.value, installed.value, pageReady\)/);
 assert(show.indexOf('pageReady = true')>show.indexOf('restoreAnalyticsQuery('));assert(show.indexOf('pageReady = true')<show.indexOf('} catch (e)'));
 assert.equal((show.match(/await execute\(/g)||[]).length,1);assert.match(show,/if \(inspection\) await execute\(inspection\)/);
 assert.doesNotMatch(show,/execute\("(?:run|policies|server-report)"\)/);
 const fixtures=await read('panel-integration/scripts/test-deferred-workspace.mjs');
 assert.match(fixtures,/ts.transpileModule\(source/);assert(fixtures.includes('partial installation state must not authorize an action'));
 const contracts=JSON.parse(await read('registry/functional-contracts.json')),row=contracts.apps.find(a=>a.id==='apache-waf');
 assert.equal(contracts.commercial_feature_parity_complete,false);
 assert(row.scenarios.some(s=>s.includes('ADI')&&s.includes('两次真实桌面打开')&&s.includes('375px')&&s.includes('inode')));
 assert(row.boundaries.some(s=>s.includes('history.sqlite')&&s.includes('原失败与诊断保留')&&s.includes('activity POST')));
 assert(row.gaps.some(s=>s.includes('完整请求体解析')));
});
test('primary quota fallback remains an official bounded protocol, never an access or signature bypass',async()=>{
 const code=await read('panel-integration/internal/appcatalog/github_catalog_git.go');
 assert.match(code,/https:\/\/github.com\/yunzhanlin\/yunzhan-apps.git\/info\/refs\?service=git-upload-pack/);assert.match(code,/!c.githubRetry.primaryQuota/);
 assert.match(code,/githubGitAdvertisementLimit = 128 << 10/);assert.match(code,/githubGitAdvertisementPacketLimit = 8192/);assert.match(code,/githubGitAdvertisementRefLimit = 512/);assert.match(code,/offset != len\(raw\)/);assert.match(code,/seen\[name\]/);assert.match(code,/name == "refs\/heads\/main"/);
 assert.doesNotMatch(code,/os\/exec|InsecureSkipVerify|Authorization|Cookie/);
 const checks=await read('panel-integration/internal/appcatalog/github_catalog_git_test.go');assert.equal((checks.match(/^func TestGitCatalog/gm)||[]).length,9);
 for(const name of ['FallbackNeverActivatesForAccessOrSecondaryRefusal','SignatureRollbackAndSameVersionImmutabilityRemainRequired','CancellationNeverStartsFallback','ConcurrentFailedFallbackDoesNotBurstEitherService'])assert(checks.includes('TestGitCatalog'+name));
 const contracts=JSON.parse(await read('registry/functional-contracts.json'));assert.equal(contracts.apps.length,50);assert.equal(contracts.commercial_feature_parity_complete,false);
 const waf=contracts.apps.find(a=>a.id==='apache-waf');assert(waf.boundaries.some(s=>s.includes('ABH')&&s.includes('这不证明全部 50 项、跨账户权限、原面板交付或所有系统业务验收')));
});
