import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {officialCatalogBaseURL} from '../tools/official-channel.mjs';
import {candidateSource} from '../tools/candidate-source.mjs';
import {createHash,createPublicKey,verify} from 'node:crypto';
import {readPreStreamPublication} from './helpers/pre-stream-publication.mjs';
const read=p=>readFile(new URL('../'+p,import.meta.url),'utf8');

test('publisher channels are two closed official paths without arbitrary URL or fallback',()=>{
  assert.equal(officialCatalogBaseURL(),'https://raw.githubusercontent.com/yunzhanlin/yunzhan-apps/main');
  assert.equal(officialCatalogBaseURL('candidate'),'https://raw.githubusercontent.com/yunzhanlin/yunzhan-apps/refs/heads/codex/app-candidate/candidate');
  for(const value of ['',null,true,{},[], 'main','Stable','candidate\n','https://untrusted.invalid','candidate/../../main'])assert.throws(()=>officialCatalogBaseURL(value));
});

test('actual catalogue URLs agree with the publisher channel and immutable versions',async()=>{
  const source=JSON.parse(await read('registry/apps.json')),catalog=JSON.parse(await read('dist/catalog-v1.json'));
  const base=officialCatalogBaseURL(source.channel===undefined?'stable':source.channel);
  assert.equal(catalog.apps.length,50);
  for(const item of catalog.apps)assert.equal(item.package_url,`${base}/dist/apps/${item.id}/${item.version}/manifest.json`);
  assert.equal(JSON.parse(await read('dist/apps/load-balance/1.8.5/manifest.json')).version,'1.8.5');
  assert.equal(JSON.parse(await read('registry/functional-contracts.json')).commercial_feature_parity_complete,false);
});

test('separate candidate catalogue changes exactly its declared known identities and never mutates stable metadata',async()=>{
  const stable=JSON.parse(await read('registry/apps.json')),patch=JSON.parse(await read('registry/candidate-apps.json'));
  const before=JSON.stringify(stable),source=candidateSource(stable,patch),catalog=JSON.parse(await read('candidate/dist/catalog-v1.json'));
  assert.equal(JSON.stringify(stable),before);assert.equal(source.apps.length,50);
  const changes=source.apps.filter((a,i)=>JSON.stringify(a)!==JSON.stringify(stable.apps[i])).map(a=>a.id);
  assert.deepEqual(changes,['load-balance']);assert.equal(stable.apps.find(a=>a.id==='load-balance').version,'1.8.5');
  assert.equal(source.apps.find(a=>a.id==='load-balance').version,'1.9.0');
  for(const item of catalog.apps)assert.equal(item.package_url,`${officialCatalogBaseURL('candidate')}/dist/apps/${item.id}/${item.version}/manifest.json`);
  for(const changed of [{...patch,channel:'https://untrusted.invalid'}, {...patch,apps:[patch.apps[0],patch.apps[0]]}, {...patch,apps:[{...patch.apps[0],id:'unknown-application'}]}, {...patch,key:'untrusted'}])assert.throws(()=>candidateSource(stable,changed));
});

test('both real signatures are valid while stable publication remains byte-identical to the authentic predecessor',async()=>{
  const key=await read('signatures/catalog-v1.pub.pem');
  assert.equal(createHash('sha256').update(key).digest('hex'),'659ea4edcecaf23a586e2ff371616fde5f6ee7c219fb70fa978816e2b10acf75');
  for(const prefix of ['', 'candidate/']){
    const raw=await read(prefix+'dist/catalog-v1.json'),bundle=JSON.parse(await read(prefix+'signatures/catalog-v1.bundle.json'));
    assert.equal(bundle.catalog,raw);assert(verify(null,Buffer.from(raw),createPublicKey(key),Buffer.from(bundle.signature,'base64')));
  }
  for(const name of ['registry/apps.json','schema/app.schema.json','dist/catalog-v1.json','signatures/catalog-v1.sig','signatures/catalog-v1.bundle.json','signatures/catalog-v1.pub.pem'])assert.equal(await read(name),readPreStreamPublication(name));
});
