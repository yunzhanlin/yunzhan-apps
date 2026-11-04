import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {validateManifest,canonical,sha256} from '../tools/lib.mjs';
import {apacheNativeCCCases} from '../tools/apache-native-cc-fixtures.mjs';
import {schemaBeforeApacheCC} from './helpers/apache-cc-schema.mjs';
const read=async n=>JSON.parse(await readFile(new URL('../'+n,import.meta.url)));
test('CC publication rejects borrowed, partial, reversed, duplicate and future authority',async()=>{
 const app=await read('candidate/dist/apps/apache-waf/2.5.0/manifest.json');
 const cases=apacheNativeCCCases(app);assert.equal(cases.length,28);
 for(const c of cases)assert.equal(validateManifest(c.manifest).length===0,c.valid,c.name);
 assert.deepEqual(validateManifest(await read('candidate/dist/apps/apache-waf/2.4.0/manifest.json')),[],'unchanged body-only application remains installable');
 assert.deepEqual(app.required_panel_features,['apache-native-body-site-transactions-v1','apache-native-cc-site-transactions-v1']);
 assert.equal(app.version,'2.5.0');assert.deepEqual(await read('candidate/dist/apps/apache-waf/2.5.0/manifest.json'),app);
});
test('CC schema extension preserves every original predicate and historical manifest byte',async()=>{
 const schemas=await Promise.all(['schema/app.schema.json','candidate/schema/app.schema.json'].map(read));assert.deepEqual(schemas[0],schemas[1]);
 for(const schema of schemas){assert.equal(sha256(canonical(schemaBeforeApacheCC(schema))),'4f0e6b862ec021eb3483f7b801ebf35328d635c07d8c3395a628e77349d30441');
  const changed=structuredClone(schema);changed.properties.name.maxLength++;assert.throws(()=>schemaBeforeApacheCC(changed),/Every pre(?:CC|Archive)/);
  const incomplete=structuredClone(schema);incomplete.allOf[0].then.oneOf.at(-1).properties.required_panel_features.prefixItems.reverse();assert.throws(()=>schemaBeforeApacheCC(incomplete));
 }
 assert.equal(sha256(await readFile(new URL('../candidate/dist/apps/apache-waf/2.4.0/manifest.json',import.meta.url))),'24c70a38581a46593ad404f07b9ba12e60e8434a2bfacaf36255942063a41038');
 assert.equal(sha256(await readFile(new URL('../dist/apps/apache-waf/2.3.0/manifest.json',import.meta.url))),'77be45eb12785e802943d26bde3fcb76eb3e4cc9bc264f387e67be290f7be6bb');
});
