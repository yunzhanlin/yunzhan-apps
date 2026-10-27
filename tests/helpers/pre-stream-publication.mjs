// Test-only reader of the real immutable PREVIOUS publication. It never
// substitutes bytes in a production client or claims the current candidate
// catalogue is unchanged. Current catalogue/manifest/signature tests run on
// the actual current files independently.
import fs from 'node:fs';
import path from 'node:path';
import assert from 'node:assert/strict';
import {createHash,createPublicKey,verify} from 'node:crypto';
import {fileURLToPath} from 'node:url';
const root=fileURLToPath(new URL('../../',import.meta.url));
const base=path.join(root,'registry/reviewed-catalogs/before-load-balance-stream-20261027');
const sha=b=>createHash('sha256').update(b).digest('hex');
const read=name=>{
  assert(typeof name==='string'&&path.posix.normalize(name)===name&&!path.isAbsolute(name)&&!name.split('/').includes('..'));
  const file=path.join(base,name),s=fs.lstatSync(file);assert(s.isFile()&&!s.isSymbolicLink()&&s.nlink===1&&s.size<2<<20);
  assert.equal(fs.realpathSync(file),file);return fs.readFileSync(file);
};
const index=JSON.parse(read('snapshot-index.json'));
assert(index.format===1&&index.source_revision==='b6923bba32cb6980c5c30011131356ca9d6c3b82'&&Object.keys(index.files).length===110);
const raw=read('dist/catalog-v1.json'),pub=read('signatures/catalog-v1.pub.pem'),signature=read('signatures/catalog-v1.sig').toString().trim();
assert.equal(sha(raw),'247c8db6cc762413c0779f8cb8a251b16d01b641b109981f084076c20f104813');
assert.equal(sha(pub),'659ea4edcecaf23a586e2ff371616fde5f6ee7c219fb70fa978816e2b10acf75');
assert(fs.readFileSync(path.join(root,'signatures/catalog-v1.pub.pem')).equals(pub),'current application trust must not change');
assert(verify(null,raw,createPublicKey(pub),Buffer.from(signature,'base64')));
const bundle=JSON.parse(read('signatures/catalog-v1.bundle.json'));assert.equal(bundle.catalog,raw.toString());assert.equal(bundle.signature,signature);
for(const [name,digest]of Object.entries(index.files))assert.equal(sha(read(name)),digest,name);
const catalog=JSON.parse(raw);assert.equal(catalog.apps.length,50);assert.equal(new Set(catalog.apps.map(a=>a.id)).size,50);
for(const app of catalog.apps){const name=`dist/apps/${app.id}/${app.version}/manifest.json`;assert.equal(sha(read(name)),app.sha256);assert.equal(read(name+'.sha256').toString(),app.sha256+'  manifest.json\n');}
export function readPreStreamPublication(name,encoding='utf8') {
  assert(Object.hasOwn(index.files,name),'not an original published predecessor member');
  const bytes=read(name);assert.equal(sha(bytes),index.files[name]);return encoding===null?bytes:bytes.toString(encoding);
}
