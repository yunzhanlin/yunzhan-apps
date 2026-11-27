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

const beforeApacheIndexRaw=await read('tests/fixtures/before-apache271-publication/inventory.json');
assert.equal(sha(beforeApacheIndexRaw),'e30d728afcb3a55f1a41be59198b6d99724f8da461d909c8d66d39f710c50914');const beforeApacheIndex=JSON.parse(beforeApacheIndexRaw);
assert.equal(beforeApacheIndex.commit,'1ae613d9fc51c3b2c57da3f25ed7cd68d20ec923');
const reviewedPM2Publication=async p=>{const raw=await read('tests/fixtures/before-apache271-publication/'+p);assert.equal(sha(raw),beforeApacheIndex.files[p]);return raw;};

test('authentic signed40 PM2 publication retains retirement and advances only the reviewed PM2 archive package',async()=>{
 const key=await read('signatures/catalog-v1.pub.pem');
 for(const prefix of['','candidate/']){
  const raw=await (prefix?reviewedPM2Publication:read)(prefix+'dist/catalog-v1.json'),catalog=JSON.parse(raw),old=JSON.parse(await retiredPublication(prefix+'dist/catalog-v1.json'));
  assert.equal(catalog.apps.length,40);assert.equal(new Set(catalog.apps.map(a=>a.id)).size,40);
  assert(verify(null,raw,createPublicKey(key),Buffer.from((await (prefix?reviewedPM2Publication:read)(prefix+'signatures/catalog-v1.sig')).toString().trim(),'base64')));
  assert.deepEqual(catalog.apps.filter(a=>a.id!=='pm2-manager'),old.apps.filter(a=>a.id!=='pm2-manager'));
  const pm2=catalog.apps.find(a=>a.id==='pm2-manager');
  if(prefix==='')assert.deepEqual(pm2,old.apps.find(a=>a.id==='pm2-manager'));
  else{assert.equal(pm2.version,'7.0.4-compat12');assert.deepEqual(JSON.parse(await read(prefix+'dist/apps/'+pm2.id+'/'+pm2.version+'/manifest.json')).required_panel_features,['pm2-configuration-archive-v1']);}
  for(const id of RETIRED_PHP_IDS){assert(!catalog.apps.some(a=>a.id===id));await assert.rejects(access(new URL('../'+prefix+'dist/apps/'+id,import.meta.url)));}
  for(const app of catalog.apps)assert.equal(sha(await read(prefix+'dist/apps/'+app.id+'/'+app.version+'/manifest.json')),app.sha256);
 }
});


test('authentic signed40 Apache publication preserves PM2 and every retired PHP removal',async()=>{
 const raw=await read('tests/fixtures/before-mobile-web140-publication/candidate/dist/catalog-v1.json');assert.equal(sha(raw),'c4860ba82898bd9f4f15644ea1b6839f4af99b6234dbd0f211f78c3090fc69be');const current=JSON.parse(raw),before=JSON.parse(await reviewedPM2Publication('candidate/dist/catalog-v1.json'));
 assert(verify(null,raw,createPublicKey(await read('signatures/catalog-v1.pub.pem')),Buffer.from((await read('tests/fixtures/before-mobile-web140-publication/candidate/signatures/catalog-v1.sig')).toString().trim(),'base64')));
 assert.equal(current.apps.length,40);assert.equal(new Set(current.apps.map(a=>a.id)).size,40);
 assert.deepEqual(current.apps.filter(a=>a.id!=='apache'),before.apps.filter(a=>a.id!=='apache'));
 const app=current.apps.find(a=>a.id==='apache');assert.equal(app.version,'2.4.71-compat1');assert.equal(app.target,'apache-2.4.71');assert.equal(app.sha256,'aadc8489fe1e4e9bb40310bafdba7a8385fd11aabe7dd97758c17b45ba98ff53');
 assert.equal(sha(await read('candidate/dist/apps/apache/2.4.71-compat1/manifest.json')),app.sha256);
 assert.equal(sha(await read('candidate/dist/apps/apache/2.4.68-compat1/manifest.json')),'abb627840489dee4ac93f8e3c925d5b6af50454caeb6655d73458aac03f60446');
 for(const id of RETIRED_PHP_IDS){assert(!current.apps.some(a=>a.id===id));await assert.rejects(access(new URL('../candidate/dist/apps/'+id,import.meta.url)));}
 for(const item of current.apps)assert.equal(sha(await read('candidate/dist/apps/'+item.id+'/'+item.version+'/manifest.json')),item.sha256);
});

test('current original-key signed40 changes only mobile140 after the authentic Apache publication',async()=>{
 const raw=await read('candidate/dist/catalog-v1.json'),current=JSON.parse(raw),oldRaw=await read('tests/fixtures/before-mobile-web140-publication/candidate/dist/catalog-v1.json');assert.equal(sha(oldRaw),'c4860ba82898bd9f4f15644ea1b6839f4af99b6234dbd0f211f78c3090fc69be');const old=JSON.parse(oldRaw),key=createPublicKey(await read('signatures/catalog-v1.pub.pem'));assert(verify(null,raw,key,Buffer.from((await read('candidate/signatures/catalog-v1.sig')).toString().trim(),'base64')));assert(verify(null,oldRaw,key,Buffer.from((await read('tests/fixtures/before-mobile-web140-publication/candidate/signatures/catalog-v1.sig')).toString().trim(),'base64')));assert.equal(current.apps.length,40);assert.deepEqual(current.apps.filter(a=>a.id!=='mobile'),old.apps.filter(a=>a.id!=='mobile'));const app=current.apps.find(a=>a.id==='mobile');assert.equal(app.version,'1.4.0');assert.equal(app.sha256,'6b6f78237d29089c0be23ed3194fa401123876b79e56e374b8c7b80d2b00bb0f');for(const item of current.apps)assert.equal(sha(await read('candidate/dist/apps/'+item.id+'/'+item.version+'/manifest.json')),item.sha256);
});
