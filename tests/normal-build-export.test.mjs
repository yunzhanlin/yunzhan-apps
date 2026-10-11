import test from 'node:test';import assert from 'node:assert/strict';import {readFile} from 'node:fs/promises';import {createHash} from 'node:crypto';
const read=p=>readFile(new URL('../'+p,import.meta.url),'utf8');
test('every actual BECJ Node build gate is exported and pinned to the same frozen release',async()=>{
 const index=JSON.parse(await read('panel-integration/source-sha256.json')),release=JSON.parse(await read('panel-integration/release-source-inputs.json'));
 assert.equal(release.archive_sha256,'804d171f2176266810d9443f00161be9a9a8b6fe5a24e579f6a8678b63842d8b');assert.equal(release.frozen_inputs_sha256,'e236058a7dfae0e050bc7a04bbdd89dcea3b78af5321b2fafa1b6bd5a4241c0e');
 const build=await read('panel-integration/packaging/build-release.sh');
 const invoked=[...new Set([...build.matchAll(/node (?:--test )?(scripts\/test-[a-z0-9-]+\.mjs)/g)].map(m=>m[1]))].sort();
 const exported=Object.keys(release.files).filter(f=>/^scripts\/test-[a-z0-9-]+\.mjs$/.test(f)).sort();assert.equal(invoked.length,35);assert.deepEqual(exported,invoked);
 for(const file of invoked){const sha=createHash('sha256').update(await read('panel-integration/'+file)).digest('hex');assert.equal(index.files[file],sha);assert.equal(release.files[file],sha);}
 const contracts=JSON.parse(await read('registry/functional-contracts.json'));assert.equal(contracts.commercial_feature_parity_complete,false);assert.equal(contracts.reviewed_normal_release.all_50_commercial,false);assert.equal(contracts.reviewed_normal_release.main_release_delivered,true);
});
