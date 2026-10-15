// Verify BOTH real signed boundaries. Never synthesize a historical catalog.
import {readFile} from 'node:fs/promises';import assert from 'node:assert/strict';
import {createHash,createPublicKey,verify} from 'node:crypto';
const read=p=>readFile(new URL('../'+p,import.meta.url)),sha=b=>createHash('sha256').update(b).digest('hex');
export const disk130Archive='registry/reviewed-catalogs/before-disk1.4-24bfod/';
export async function catalogBeforeDisk140Bytes(current){
 const r=JSON.parse(await read('registry/disk-host-app-release.json')),oldRaw=await read(disk130Archive+'catalog-v1.json'),latestRaw=await read('dist/catalog-v1.json'),pub=await read('signatures/catalog-v1.pub.pem');
 assert.equal(sha(pub),'659ea4edcecaf23a586e2ff371616fde5f6ee7c219fb70fa978816e2b10acf75');assert.equal(sha(oldRaw),'fccca3c9e925e21b298d38a56c2bee9af15c6896ab514e931eb6d977aaa79ad3');assert.equal(sha(oldRaw),r.previous_catalog_sha256);assert.equal(sha(latestRaw),r.new_catalog_sha256);
 for(const [prefix,bytes]of [[disk130Archive,oldRaw],['signatures/',latestRaw]]){
  const sig=(await read(prefix+'catalog-v1.sig')).toString().trim(),b=JSON.parse(await read(prefix+'catalog-v1.bundle.json'));assert.equal(b.catalog,bytes.toString());assert.equal(b.signature,sig);assert(verify(null,bytes,createPublicKey(pub),Buffer.from(sig,'base64')));
 }
 assert.equal(sha(await read(disk130Archive+'catalog-v1.pub.pem')),sha(pub));assert.equal((await read(disk130Archive+'catalog-v1.json.sha256')).toString(),sha(oldRaw)+'  catalog-v1.json\n');
 const old=JSON.parse(oldRaw),latest=JSON.parse(latestRaw);assert.equal(old.apps.length,50);assert.equal(latest.apps.length,50);assert.deepEqual(latest.apps.map(a=>a.id),old.apps.map(a=>a.id));assert(Date.parse(latest.generated_at)>Date.parse(old.generated_at));assert.deepEqual(latest.apps.filter(a=>a.id!=='disk-analysis'),old.apps.filter(a=>a.id!=='disk-analysis'));
 const before=old.apps.find(a=>a.id==='disk-analysis'),after=latest.apps.find(a=>a.id==='disk-analysis');assert.equal(before.version,'1.3.0');assert.equal(before.sha256,'4c971c1c079efb3b5b453d3906371284893ac6e06e5b4a4aa4359c680afd2a38');assert.equal(after.version,'1.4.0');assert.equal(after.sha256,r.application_manifest_sha256);
 for(const a of [before,after])assert.equal(sha(await read('dist/apps/disk-analysis/'+a.version+'/manifest.json')),a.sha256);
 if(current!==undefined){const s=JSON.stringify(current);assert(s===JSON.stringify(old)||s===JSON.stringify(latest),'not exact old13 or current14 signed object');}
 return oldRaw;
}
export async function catalogBeforeDisk140(current){return JSON.parse(await catalogBeforeDisk140Bytes(current));}
