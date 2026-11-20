import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile,access} from 'node:fs/promises';
import {createHash,createPublicKey,verify} from 'node:crypto';
import {ACTIVE_APPLICATION_COUNT,RETIRED_PHP_IDS} from '../tools/active-apps.mjs';
import {candidateSource} from '../tools/candidate-source.mjs';
const read=p=>readFile(new URL('../'+p,import.meta.url));
const json=async p=>JSON.parse(await read(p));
const sha=b=>createHash('sha256').update(b).digest('hex');
const inventoryRaw=await read('tests/fixtures/after-php8-retirement/inventory.json');assert.equal(sha(inventoryRaw),'79b4673b9dd6be176fa9893131ee9ff40b97880454243c95799d1548a945d7ac');const inventory=JSON.parse(inventoryRaw);
const retiredPublication=async p=>{const raw=await read('tests/fixtures/after-php8-retirement/'+p);assert.equal(sha(raw),inventory.publications[p]);return raw;};
test('authentic signed retirement channels remove exactly ten pre8 PHP applications and preserve every other package',async()=>{
 assert.equal(ACTIVE_APPLICATION_COUNT,40);assert.equal(RETIRED_PHP_IDS.length,10);
 const key=await read('signatures/catalog-v1.pub.pem');
 assert.equal(sha(key),'659ea4edcecaf23a586e2ff371616fde5f6ee7c219fb70fa978816e2b10acf75');
 for(const prefix of['','candidate/']){
  const raw=await retiredPublication(prefix+'dist/catalog-v1.json'),catalog=JSON.parse(raw),before=await json('tests/fixtures/before-php8-retirement/'+prefix+'dist/catalog-v1.json');
  assert.equal(catalog.apps.length,40);assert.equal(new Set(catalog.apps.map(a=>a.id)).size,40);
  assert.deepEqual(catalog.apps,before.apps.filter(a=>!RETIRED_PHP_IDS.includes(a.id)));
  const signature=(await retiredPublication(prefix+'signatures/catalog-v1.sig')).toString().trim();
  assert(verify(null,raw,createPublicKey(key),Buffer.from(signature,'base64')));
  for(const id of RETIRED_PHP_IDS){assert(!catalog.apps.some(a=>a.id===id));await assert.rejects(access(new URL('../'+prefix+'dist/apps/'+id,import.meta.url)));}
  for(const app of catalog.apps)assert.equal(sha(await read(prefix+'dist/apps/'+app.id+'/'+app.version+'/manifest.json')),app.sha256);
  for(const id of['php-80','php-81','php-82','php-83','php-84','php-85'])assert(catalog.apps.some(a=>a.id===id));
 }
 const stable=await json('registry/apps.json'),patch=await json('registry/candidate-apps.json');
 assert.equal(candidateSource(stable,patch).apps.length,40);
 for(const id of RETIRED_PHP_IDS){const app=(await json('tests/fixtures/before-php8-retirement/registry/apps.json')).apps.find(a=>a.id===id);assert.throws(()=>candidateSource({...stable,apps:[...stable.apps.slice(1),app]},patch));}
});

test('current signed40 retains retirement and advances only the reviewed PM2 archive package',async()=>{
 const key=await read('signatures/catalog-v1.pub.pem');
 for(const prefix of['','candidate/']){
  const raw=await read(prefix+'dist/catalog-v1.json'),catalog=JSON.parse(raw),old=JSON.parse(await retiredPublication(prefix+'dist/catalog-v1.json'));
  assert.equal(catalog.apps.length,40);assert.equal(new Set(catalog.apps.map(a=>a.id)).size,40);
  assert(verify(null,raw,createPublicKey(key),Buffer.from((await read(prefix+'signatures/catalog-v1.sig')).toString().trim(),'base64')));
  assert.deepEqual(catalog.apps.filter(a=>a.id!=='pm2-manager'),old.apps.filter(a=>a.id!=='pm2-manager'));
  const pm2=catalog.apps.find(a=>a.id==='pm2-manager');
  if(prefix==='')assert.deepEqual(pm2,old.apps.find(a=>a.id==='pm2-manager'));
  else{assert.equal(pm2.version,'7.0.4-compat12');assert.deepEqual(JSON.parse(await read(prefix+'dist/apps/'+pm2.id+'/'+pm2.version+'/manifest.json')).required_panel_features,['pm2-configuration-archive-v1']);}
  for(const id of RETIRED_PHP_IDS){assert(!catalog.apps.some(a=>a.id===id));await assert.rejects(access(new URL('../'+prefix+'dist/apps/'+id,import.meta.url)));}
  for(const app of catalog.apps)assert.equal(sha(await read(prefix+'dist/apps/'+app.id+'/'+app.version+'/manifest.json')),app.sha256);
 }
});
