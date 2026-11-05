import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import {fileURLToPath}from 'node:url';
import {createPublicKey,verify}from 'node:crypto';
import {filesSyncUnpublishedCases}from '../tools/files-sync-unpublished-fixtures.mjs';
import {validateManifest,canonical,sha256}from '../tools/lib.mjs';
import {schemaBeforeFilesSyncUnpublished}from './helpers/files-sync-unpublished-schema.mjs';
const root=fileURLToPath(new URL('../',import.meta.url)),read=n=>fs.readFileSync(root+n),json=n=>JSON.parse(read(n));
for(const c of filesSyncUnpublishedCases(root))test('files-sync201 exact unpublished retention ABI: '+c.name,()=>assert.equal(validateManifest(c.manifest).length===0,c.valid,c.name));
test('retention extension removes only its exact addition and preserves every original C63 predicate',()=>{
 for(const name of ['schema/app.schema.json','candidate/schema/app.schema.json']){
  const current=json(name),original=JSON.stringify(current);assert.equal(sha256(canonical(schemaBeforeFilesSyncUnpublished(current))),'70baea6205b2aa7243107b716c6007c9c8d5859a81b83d01e8f7c50ea08f38ef');assert.equal(JSON.stringify(current),original);
 }
});
for(const kind of ['missing-feature','duplicate-feature','missing-branch','changed-branch','missing-guard','missing-version-alternative','missing-old-ABI-alternative','unrelated'])test('retention predecessor inversion refuses '+kind,()=>{
 const s=json('schema/app.schema.json'),flags=s.properties.required_panel_features.items.enum;
 if(kind==='missing-feature')flags.pop();if(kind==='duplicate-feature')flags.push(flags.at(-1));
 if(kind==='missing-branch')s.allOf[0].then.oneOf.pop();if(kind==='changed-branch')s.allOf[0].then.oneOf.at(-1).properties.version.const='2.0.2';
 if(kind==='missing-guard')s.allOf.pop();if(kind==='missing-version-alternative')s.allOf[32].then.anyOf.pop();if(kind==='missing-old-ABI-alternative')s.allOf[33].then.anyOf.pop();if(kind==='unrelated')s.title='unreviewed';
 assert.throws(()=>schemaBeforeFilesSyncUnpublished(s));
});
test('the original signed C63 fifty, all49 other entries and old200 endpoint remain byte-exact',()=>{
 const base='registry/reviewed-catalogs/before-native-filesync201-c64/',receipt=json(base+'snapshot.json');assert.equal(receipt.original_publisher_head,'04555b0f1e102ebf8ad385351784cf33697ee194');assert.equal(Object.keys(receipt.files_sha256).length,105);
 for(const[n,hash]of Object.entries(receipt.files_sha256))assert.equal(sha256(read(base+n)),hash,n);
 assert(verify(null,read(base+'dist/catalog-v1.json'),createPublicKey(read(base+'signatures/catalog-v1.pub.pem')),Buffer.from(read(base+'signatures/catalog-v1.sig').toString().trim(),'base64')));
 const old=json(base+'dist/catalog-v1.json').apps,current=json('candidate/dist/catalog-v1.json').apps;assert.equal(old.length,50);assert.equal(current.length,50);
 const before=new Map(old.map(a=>[a.id,a])),after=new Map(current.map(a=>[a.id,a]));assert.deepEqual([...before.keys()],[...after.keys()]);
 assert.deepEqual([...before.keys()].filter(id=>JSON.stringify(before.get(id))!==JSON.stringify(after.get(id))),['files-sync']);assert.equal(before.get('files-sync').version,'2.0.0');assert.equal(after.get('files-sync').version,'2.0.1');
 for(const a of old){const n='dist/apps/'+a.id+'/'+a.version+'/manifest.json';assert.equal(sha256(read('candidate/'+n)),receipt.files_sha256[n]);}
});
