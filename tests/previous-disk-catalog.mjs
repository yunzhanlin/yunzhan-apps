import assert from 'node:assert/strict';
import {catalogBeforeDisk140Bytes,disk130Archive} from './previous-disk-host-catalog.mjs';
import {readFile} from 'node:fs/promises';
import {createHash,createPublicKey,verify} from 'node:crypto';
const read=p=>readFile(new URL('../'+p,import.meta.url)),sha=b=>createHash('sha256').update(b).digest('hex');

// Return the ORIGINAL signed pre-disk1.3 bytes. Never rewrite an earlier
// other49 digest or synthesize a catalog and pretend it was signed historically.
export async function catalogBeforeDisk130Bytes(current){
 const r=JSON.parse(await read('registry/disk-inode-update-release.json')),raw=await read('registry/reviewed-catalogs/before-disk1.3-24bfin/catalog-v1.json'),latestRaw=await catalogBeforeDisk140Bytes(),key=await read('signatures/catalog-v1.pub.pem');
 assert.equal(sha(raw),r.previous_catalog_sha256);assert.equal(sha(latestRaw),r.new_catalog_sha256);assert.equal(sha(key),'659ea4edcecaf23a586e2ff371616fde5f6ee7c219fb70fa978816e2b10acf75');
 for(const [root,bytes]of [['registry/reviewed-catalogs/before-disk1.3-24bfin/',raw],[disk130Archive,latestRaw]]){
  const b=JSON.parse(await read(root+'catalog-v1.bundle.json')),signature=(await read(root+'catalog-v1.sig')).toString().trim();assert.equal(b.catalog,bytes.toString());assert.equal(b.signature,signature);assert(verify(null,bytes,createPublicKey(key),Buffer.from(signature,'base64')));
 }
 const old=JSON.parse(raw),latest=JSON.parse(latestRaw);assert.equal(old.apps.length,50);assert.equal(latest.apps.length,50);assert.deepEqual(latest.apps.map(a=>a.id),old.apps.map(a=>a.id));assert(Date.parse(latest.generated_at)>Date.parse(old.generated_at));
 assert.deepEqual(latest.apps.filter(a=>a.id!=='disk-analysis'),old.apps.filter(a=>a.id!=='disk-analysis'));
 const before=old.apps.find(a=>a.id==='disk-analysis'),after=latest.apps.find(a=>a.id==='disk-analysis');assert.equal(before.version,'1.2.0');assert.equal(before.sha256,r.original_1_2_manifest_sha256);assert.equal(after.version,'1.3.0');assert.equal(after.sha256,r.application_manifest_sha256);
 for(const a of [before,after])assert.equal(sha(await read('dist/apps/disk-analysis/'+a.version+'/manifest.json')),a.sha256);
 // Some historical readers are nested. Accept only either exact signed
 // catalog object after BOTH boundaries above are verified, never a mutation.
 const encoded=JSON.stringify(current);assert(encoded===JSON.stringify(latest)||encoded===JSON.stringify(old)||encoded===JSON.stringify(JSON.parse(await read('dist/catalog-v1.json'))),'not the exact current or preserved original signed catalog');
 return raw;
}
export async function catalogBeforeDisk130(current){return JSON.parse(await catalogBeforeDisk130Bytes(current));}
