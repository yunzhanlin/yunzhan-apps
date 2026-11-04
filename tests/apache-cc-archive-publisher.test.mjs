import test from'node:test';import assert from'node:assert/strict';import{readFile}from'node:fs/promises';
import{apacheCCArchiveCases}from'../tools/apache-cc-archive-fixtures.mjs';import{validateManifest,canonical,sha256}from'../tools/lib.mjs';import{schemaBeforeApacheCCArchive}from'./helpers/apache-cc-archive-schema.mjs';
const read=async n=>JSON.parse(await readFile(new URL('../'+n,import.meta.url)));
test('archive251 requires all three exact ordered handlers and preserves old250 manifest bytes',async()=>{
 const app=(await read('registry/candidate-apps.json')).apps.find(a=>a.id==='apache-waf'),cases=apacheCCArchiveCases(app);assert.equal(cases.length,26);
 for(const c of cases)assert.equal(validateManifest(c.manifest).length===0,c.valid,c.name);
 assert.equal(app.version,'2.5.1');assert.deepEqual(app.required_panel_features,['apache-native-body-site-transactions-v1','apache-native-cc-site-transactions-v1','apache-cc-log-archive-v1']);assert.deepEqual(await read('candidate/dist/apps/apache-waf/2.5.1/manifest.json'),app);
 assert.equal(sha256(await readFile(new URL('../candidate/dist/apps/apache-waf/2.5.0/manifest.json',import.meta.url))),'fa070a05545a057150c8e1352378c8b41b31416cd6996351a1302e2b0d6c24b9');
});
test('archive schema addition cannot hide omitted or altered prior predicates',async()=>{
 const schema=await read('schema/app.schema.json'),previous=schemaBeforeApacheCCArchive(schema),delivered=await read('candidate/schema/app.schema.json');assert.deepEqual(schema,delivered);
 assert.equal(previous.properties.required_panel_features.items.enum.includes('apache-cc-log-archive-v1'),false);
 for(const change of [s=>s.properties.name.maxLength++,s=>s.allOf[0].then.oneOf.at(-1).properties.required_panel_features.prefixItems.reverse(),s=>s.properties.required_panel_features.items.enum.push('apache-cc-log-archive-v1')]){const altered=structuredClone(schema);change(altered);assert.throws(()=>schemaBeforeApacheCCArchive(altered));}
 assert.equal(sha256(canonical(previous)),sha256(canonical(schemaBeforeApacheCCArchive(delivered))));
});
