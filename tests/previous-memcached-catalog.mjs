// Real independently signed boundaries; never rewrite an older acceptance claim.
import {readFile} from'node:fs/promises';import assert from'node:assert/strict';import{createHash,createPublicKey,verify}from'node:crypto';
import {catalogBeforeAnalyticsBytes} from './previous-analytics-catalog.mjs';
import {beforeAnalytics} from './pre-analytics-workflow.mjs';
const read=p=>readFile(new URL('../'+p,import.meta.url)),sha=b=>createHash('sha256').update(b).digest('hex');
export const beforeMemcachedCompat2='registry/reviewed-catalogs/before-memcached-compat2-24bgdk/';
export async function catalogBeforeMemcachedCompat2Bytes(current){
 const oldRaw=await read(beforeMemcachedCompat2+'catalog-v1.json'),latestRaw=catalogBeforeAnalyticsBytes(),pub=await read('signatures/catalog-v1.pub.pem');
 assert.equal(sha(pub),'659ea4edcecaf23a586e2ff371616fde5f6ee7c219fb70fa978816e2b10acf75');assert.equal(sha(oldRaw),'53a3fa58943042b91709571904d4274f4af11639ef31560806d2a3c3dc7a57ad');assert.equal(sha(latestRaw),'e4ae8de3564ae2e0c3a11adc970001cecaf4933fd041e8cd970903b261049e69');
 for(const[prefix,bytes]of [[beforeMemcachedCompat2,oldRaw],[beforeAnalytics,latestRaw]]){
  const sig=(await read(prefix+'catalog-v1.sig')).toString().trim(),bundle=JSON.parse(await read(prefix+'catalog-v1.bundle.json'));assert.equal(bundle.catalog,bytes.toString());assert.equal(bundle.signature,sig);assert(verify(null,bytes,createPublicKey(pub),Buffer.from(sig,'base64')));
 }
 assert.equal(sha(await read(beforeMemcachedCompat2+'catalog-v1.pub.pem')),sha(pub));assert.equal((await read(beforeMemcachedCompat2+'catalog-v1.json.sha256')).toString(),sha(oldRaw)+'  catalog-v1.json\n');assert.equal(sha(await read(beforeMemcachedCompat2+'apps-registry.json')),'30946365aa16792818903c413c06fe0dbd53daa5162dac8c67d0d894f37cfabe');
 const old=JSON.parse(oldRaw),latest=JSON.parse(latestRaw);assert.equal(old.apps.length,50);assert.equal(latest.apps.length,50);assert.deepEqual(latest.apps.map(a=>a.id),old.apps.map(a=>a.id));assert.deepEqual(latest.apps.filter(a=>a.id!=='memcached'),old.apps.filter(a=>a.id!=='memcached'));assert(Date.parse(latest.generated_at)>Date.parse(old.generated_at));
 for(const[catalog,version,pin]of[[old,'1.6.45-compat1','0'],[latest,'1.6.45-compat2','72f10849c748254794b899c9b9787342dd4c70b66861a9ecdf6963b6e1a1f0e1']]){
  const app=catalog.apps.find(a=>a.id==='memcached');assert.equal(app.version,version);if(pin!=='0')assert.equal(app.sha256,pin);assert.equal(sha(await read('dist/apps/memcached/'+version+'/manifest.json')),app.sha256);
 }
 if(current!==undefined){if(JSON.stringify(current)===JSON.stringify(JSON.parse(await read('dist/catalog-v1.json'))))current=latest;const s=JSON.stringify(current);assert(s===JSON.stringify(old)||s===JSON.stringify(latest),'not exact pre-Memcached2 or current signed object');}
 return oldRaw;
}
