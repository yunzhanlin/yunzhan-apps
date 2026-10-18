import fs from 'node:fs';import assert from 'node:assert/strict';import {createHash,createPublicKey,verify} from 'node:crypto';
import {beforeAnalytics} from './pre-analytics-workflow.mjs';
const read=p=>fs.readFileSync(new URL('../'+p,import.meta.url)),sha=b=>createHash('sha256').update(b).digest('hex');
export function catalogBeforeAnalyticsBytes(){
 const old=read(beforeAnalytics+'catalog-v1.json'),current=read('dist/catalog-v1.json'),pub=read('signatures/catalog-v1.pub.pem');
 assert.equal(sha(pub),'659ea4edcecaf23a586e2ff371616fde5f6ee7c219fb70fa978816e2b10acf75');
 assert.equal(sha(old),'e4ae8de3564ae2e0c3a11adc970001cecaf4933fd041e8cd970903b261049e69');
 assert.equal(sha(current),'ac150c30f7d83cc0dc25218386831878d9b8deb45396e6e803fde88e6982dfd6');
 for(const [prefix,raw]of [[beforeAnalytics,old],['signatures/',current]]){
  const signature=read(prefix+'catalog-v1.sig').toString().trim(),b=JSON.parse(read(prefix+'catalog-v1.bundle.json'));
  assert.equal(b.catalog,raw.toString());assert.equal(b.signature,signature);assert(verify(null,raw,createPublicKey(pub),Buffer.from(signature,'base64')));
 }
 assert.equal(sha(read(beforeAnalytics+'apps-registry.json')),'4063f185428627e0b34e8150265a74d8245b18c667f565037ba12517c120e9c5');
 assert.equal(sha(read('registry/apps.json')),'50d7f83d189928b57d1c741a243cd65f1f7fa4b1bd0d9cee52f56f6f1ad3f7cf');
 const a=JSON.parse(old),b=JSON.parse(current);assert.equal(a.apps.length,50);assert.equal(b.apps.length,50);assert(Date.parse(b.generated_at)>Date.parse(a.generated_at));
 assert.deepEqual(b.apps.filter(a=>a.id!=='website-analytics'),a.apps.filter(a=>a.id!=='website-analytics'));
 for(const [c,v,pin]of [[a,'2.3.0','4953ee9526b5e5b189f59eed5731d2ca40f3b76c715319e215b0f3fe3a9f1ec8'],[b,'2.3.1','c33f6f987ea318dfff42c5a9a225aa4e8d123d8334f74c207dbf93e475cbb157']]){
  const item=c.apps.find(x=>x.id==='website-analytics');assert.equal(item.version,v);assert.equal(item.sha256,pin);assert.equal(sha(read('dist/apps/website-analytics/'+v+'/manifest.json')),pin);
 }
 const oldApps=JSON.parse(read(beforeAnalytics+'apps-registry.json')),newApps=JSON.parse(read('registry/apps.json'));
 assert.deepEqual(newApps.apps.filter(a=>a.id!=='website-analytics'),oldApps.apps.filter(a=>a.id!=='website-analytics'));
 return old;
}
export function preAnalyticsRead(p,bytes){
 if(p==='dist/catalog-v1.json')return catalogBeforeAnalyticsBytes();
 if(p==='registry/apps.json'){catalogBeforeAnalyticsBytes();return read(beforeAnalytics+'apps-registry.json');}
 return bytes;
}
