import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
const read=name=>readFile(new URL('../'+name,import.meta.url),'utf8');
test('remote-sync and bounded history publish distinct immutable versions with remaining limits',async()=>{
 const registry=JSON.parse(await read('registry/apps.json')),contracts=JSON.parse(await read('registry/functional-contracts.json'));
 const sync=registry.apps.find(a=>a.id==='files-sync'),stats=registry.apps.find(a=>a.id==='website-statistics-v2');
 assert.equal(sync.version,'1.7.0');assert.equal(stats.version,'2.4.0');assert.match(sync.summary,/远端实时尚未提供/);assert.match(stats.summary,/25 万行/);
 const previous=JSON.parse(await read('dist/apps/website-statistics-v2/2.3.0/manifest.json'));
 assert.equal(previous.version,'2.3.0');assert.equal(previous.id,stats.id);
 assert.equal(contracts.commercial_feature_parity_complete,false);
 for(const id of [sync.id,stats.id])assert(contracts.apps.find(a=>a.id===id).gaps.length>0);
 const source=await read('panel-integration/internal/executor/app_sync_remote_jobs_linux.go');
 assert.match(source,/"job": remotePublicJob\(old, true\)/);assert.match(source,/"job": remotePublicJob\(j, true\)/);
 assert(!source.includes('map[string]any{"job": old,'));
 const report=await read('panel-integration/web/src/AppModuleReport.vue');assert.match(report,/拟复制（尚未写入）/);
 const build=await read('panel-integration/packaging/build-release.sh');
 for(const match of build.matchAll(/scripts\/(test-[a-z0-9-]+\.mjs)/g))assert((await read('panel-integration/scripts/'+match[1])).length>0,match[1]);
});
