import test from 'node:test';import assert from 'node:assert/strict';import {readFile} from 'node:fs/promises';import {createHash} from 'node:crypto';
const read=p=>readFile(new URL('../'+p,import.meta.url),'utf8');
test('every actual BEOQ Node build gate is exported and pinned to the same frozen release',async()=>{
 const index=JSON.parse(await read('panel-integration/source-sha256.json')),release=JSON.parse(await read('panel-integration/release-source-inputs.json'));
 assert.equal(release.archive_sha256,'1b48dab44be6513c434203544ce5048aa1cab88031fed17cf4bd1c7216af1d0b');assert.equal(release.frozen_inputs_sha256,'5411b3087db37b56677b8906865896802ec772390a7179f54af50415c5677457');
 const build=await read('panel-integration/packaging/build-release.sh');
 const invoked=[...new Set([...build.matchAll(/node (?:--test )?(scripts\/test-[a-z0-9-]+\.mjs)/g)].map(m=>m[1]))].sort();
 const exported=Object.keys(release.files).filter(f=>/^scripts\/test-[a-z0-9-]+\.mjs$/.test(f)).sort();assert.equal(invoked.length,37);assert.deepEqual(exported,invoked);
 for(const file of invoked){const sha=createHash('sha256').update(await read('panel-integration/'+file)).digest('hex');assert.equal(index.files[file],sha);assert.equal(release.files[file],sha);}
 const contracts=JSON.parse(await read('registry/functional-contracts.json'));assert.equal(contracts.commercial_feature_parity_complete,false);assert.equal(contracts.reviewed_normal_release.all_50_commercial,false);assert.equal(contracts.reviewed_normal_release.main_release_delivered,true);assert.equal(contracts.previous_main_delivery.main_release_delivered,true);
});
