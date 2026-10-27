// Preserve an authentic signed predecessor, never reconstruct an old signature
// or rewrite historical success as candidate/stable installation acceptance.
import fs from 'node:fs';
import path from 'node:path';
import assert from 'node:assert/strict';
import {createHash,createPublicKey,verify} from 'node:crypto';
import {execFileSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
const root=fileURLToPath(new URL('../',import.meta.url));
const revision='b6923bba32cb6980c5c30011131356ca9d6c3b82';
const output=path.join(root,'registry/reviewed-catalogs/before-load-balance-stream-20261027');
assert.equal(process.argv.length,2,'no alternate revision, output, URL or key is accepted');
assert(!fs.existsSync(output),'retain and inspect the original outcome; do not overwrite a snapshot');
const sha=b=>createHash('sha256').update(b).digest('hex');
const read=name=>{
  assert(path.posix.normalize(name)===name&&!path.isAbsolute(name)&&!name.split('/').includes('..'));
  return execFileSync('git',['show',revision+':'+name],{cwd:root,maxBuffer:2<<20,timeout:10000});
};
const raw=read('dist/catalog-v1.json'),pub=read('signatures/catalog-v1.pub.pem'),sig=read('signatures/catalog-v1.sig');
assert.equal(sha(raw),'247c8db6cc762413c0779f8cb8a251b16d01b641b109981f084076c20f104813');
assert.equal(sha(pub),'659ea4edcecaf23a586e2ff371616fde5f6ee7c219fb70fa978816e2b10acf75');
assert(verify(null,raw,createPublicKey(pub),Buffer.from(sig.toString().trim(),'base64')));
const bundle=JSON.parse(read('signatures/catalog-v1.bundle.json'));
assert.equal(bundle.catalog,raw.toString());assert.equal(bundle.signature,sig.toString().trim());
const catalog=JSON.parse(raw);assert(catalog.apps.length===50&&new Set(catalog.apps.map(a=>a.id)).size===50);
assert.equal(catalog.apps.find(a=>a.id==='load-balance').version,'1.8.5');
const names=['registry/apps.json','dist/catalog-v1.json','dist/catalog-v1.json.sha256','signatures/catalog-v1.pub.pem','signatures/catalog-v1.sig','signatures/catalog-v1.bundle.json','.github/workflows/verify.yml','schema/app.schema.json','tools/lib.mjs','tools/build.mjs'];
for(const app of catalog.apps){
  assert(/^[a-z0-9-]+$/.test(app.id)&&/^[0-9A-Za-z.-]+$/.test(app.version));
  const name=`dist/apps/${app.id}/${app.version}/manifest.json`;
  assert.equal(sha(read(name)),app.sha256);assert.equal(read(name+'.sha256').toString(),app.sha256+'  manifest.json\n');
  names.push(name,name+'.sha256');
}
assert.equal(names.length,110);
const files=Object.fromEntries(names.map(name=>[name,read(name)]));
fs.mkdirSync(output,{mode:0o755});
for(const [name,bytes]of Object.entries(files)){
  const file=path.join(output,name);fs.mkdirSync(path.dirname(file),{recursive:true,mode:0o755});
  fs.writeFileSync(file,bytes,{flag:'wx',mode:0o644});assert(fs.readFileSync(file).equals(bytes));
}
const index={format:1,source_revision:revision,catalog_sha256:sha(raw),files:Object.fromEntries(Object.entries(files).map(([name,bytes])=>[name,sha(bytes)])),new_signature_operations:0,candidate_or_all50_acceptance:false};
fs.writeFileSync(output+'/snapshot-index.json',JSON.stringify(index,null,2)+'\n',{flag:'wx',mode:0o644});
console.log(JSON.stringify({ok:true,authentic_signed_predecessor:true,files:names.length,revision,new_signatures:0,application_requests:0}));
