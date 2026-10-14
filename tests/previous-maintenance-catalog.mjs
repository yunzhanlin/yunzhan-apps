import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {createHash,createPublicKey,verify} from 'node:crypto';
import {catalogBeforeDisk130} from './previous-disk-catalog.mjs';
const read=p=>readFile(new URL('../'+p,import.meta.url));
const sha=b=>createHash('sha256').update(b).digest('hex');

// Older release proofs keep their complete original signed catalog. Never
// change a historical other49 digest to include a later maintenance release.
export async function catalogBeforeMaintenance130(current){
 current=await catalogBeforeDisk130(current);
 const prefix='registry/reviewed-catalogs/20261013-201440/';
 const raw=await read(prefix+'catalog-v1.json');
 assert.equal(sha(raw),'e968c4fb656cad429cb7921a0277d4f83ca221130a8e78a2d19868a15c3c830d');
 const key=await read(prefix+'catalog-v1.pub.pem');
 assert.equal(sha(key),'659ea4edcecaf23a586e2ff371616fde5f6ee7c219fb70fa978816e2b10acf75');
 assert.deepEqual(key,await read('signatures/catalog-v1.pub.pem'));
 const signature=(await read(prefix+'catalog-v1.sig')).toString('utf8').trim();
 assert(verify(null,raw,createPublicKey(key),Buffer.from(signature,'base64')));
 const bundle=JSON.parse(await read(prefix+'catalog-v1.bundle.json'));
 assert.equal(bundle.catalog,raw.toString('utf8'));assert.equal(bundle.signature,signature);
 const old=JSON.parse(raw),prior=old.apps.find(a=>a.id==='platform-ops'),next=current.apps.find(a=>a.id==='platform-ops');
 assert.equal(old.apps.length,50);assert.equal(current.apps.length,50);
 assert.equal(prior.version,'1.2.0');assert.equal(prior.sha256,'2962907ca319b6266c369df203f46886609073651b2aa7f6baa316a95b885de9');
 assert.equal(sha(await read('dist/apps/platform-ops/1.2.0/manifest.json')),prior.sha256);
 assert.equal(next.version,'1.3.0');assert.equal(next.sha256,'6d433842fb11880283548bcc739d47b17c46c3d3d7242fefa1494faf9da0b346');
 assert.equal(sha(await read('dist/apps/platform-ops/1.3.0/manifest.json')),next.sha256);
 assert(Date.parse(current.generated_at)>Date.parse(old.generated_at));
 assert.deepEqual(current.apps.filter(a=>a.id!=='platform-ops'),old.apps.filter(a=>a.id!=='platform-ops'));
 return old;
}
