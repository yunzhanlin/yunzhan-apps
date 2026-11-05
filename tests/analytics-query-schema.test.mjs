import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import {fileURLToPath}from 'node:url';
import {createPublicKey,verify}from 'node:crypto';
import {analyticsQueryCases}from '../tools/analytics-query-fixtures.mjs';
import {validateManifest,canonical,sha256}from '../tools/lib.mjs';
import {schemaBeforeAnalyticsQuery}from './helpers/analytics-query-schema.mjs';
const root=fileURLToPath(new URL('../',import.meta.url)),read=n=>fs.readFileSync(root+n),json=n=>JSON.parse(read(n));
for(const c of analyticsQueryCases(root))test('analytics242 exact query ABI: '+c.name,()=>assert.equal(validateManifest(c.manifest).length===0,c.valid,c.name));
test('query extension reverses exactly to the original C62 schema and does not mutate its input',()=>{
 for(const name of ['schema/app.schema.json','candidate/schema/app.schema.json']){
  const current=json(name),before=JSON.stringify(current);
  assert.equal(sha256(canonical(schemaBeforeAnalyticsQuery(current))),'8c349cf95515f7a1678b8e8a65928da9e732772c7b8d075759f0fb2a792c4c40');
  assert.equal(JSON.stringify(current),before);
 }
});
for(const kind of ['missing-feature','duplicate-feature','missing-branch','changed-branch','missing-own-guard','missing-route-alternative','missing-version-alternative','missing-order-alternative','unrelated'])test('query predecessor schema rejects '+kind,()=>{
 const s=json('schema/app.schema.json'),flags=s.properties.required_panel_features.items.enum;
 if(kind==='missing-feature')flags.pop();if(kind==='duplicate-feature')flags.push(flags.at(-1));
 if(kind==='missing-branch')s.allOf[0].then.oneOf.pop();if(kind==='changed-branch')s.allOf[0].then.oneOf.at(-1).properties.version.const='2.4.3';
 if(kind==='missing-own-guard')s.allOf.pop();if(kind==='missing-route-alternative')s.allOf[25].then.anyOf.pop();if(kind==='missing-version-alternative')s.allOf[26].then.anyOf.pop();
 if(kind==='missing-order-alternative')s.allOf[27].then.anyOf.pop();if(kind==='unrelated')s.title='unreviewed';
 assert.throws(()=>schemaBeforeAnalyticsQuery(s));
});
test('exact signed C62 fifty and all49 unaffected current app entries remain immutable',()=>{
 const base='registry/reviewed-catalogs/before-native-analytics242-c63/',receipt=json(base+'snapshot.json');
 assert.equal(receipt.original_publisher_head,'2eb0c240387167ed6a9d477b08e7c5757c671594');assert.equal(Object.keys(receipt.files_sha256).length,105);
 for(const [name,hash]of Object.entries(receipt.files_sha256))assert.equal(sha256(read(base+name)),hash,name);
 const raw=read(base+'dist/catalog-v1.json'),key=createPublicKey(read(base+'signatures/catalog-v1.pub.pem'));
 assert(verify(null,raw,key,Buffer.from(read(base+'signatures/catalog-v1.sig').toString().trim(),'base64')));
 const old=json(base+'dist/catalog-v1.json').apps,current=json('candidate/dist/catalog-v1.json').apps;
 assert.equal(old.length,50);assert.equal(current.length,50);
 const before=new Map(old.map(a=>[a.id,a])),after=new Map(current.map(a=>[a.id,a]));assert.deepEqual([...before.keys()],[...after.keys()]);
 assert.deepEqual([...before.keys()].filter(id=>JSON.stringify(before.get(id))!==JSON.stringify(after.get(id))),['website-analytics']);
 assert.equal(before.get('website-analytics').version,'2.4.1');assert.equal(after.get('website-analytics').version,'2.4.2');
 for(const a of old){const name='dist/apps/'+a.id+'/'+a.version+'/manifest.json';assert.equal(sha256(read('candidate/'+name)),receipt.files_sha256[name]);}
});
