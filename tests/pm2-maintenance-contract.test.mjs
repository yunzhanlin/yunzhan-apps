import fs from'node:fs';
import path from'node:path';
import assert from'node:assert/strict';
import test from'node:test';
import{validateManifest,canonical,sha256}from'../tools/lib.mjs';
import{pm2MaintenanceCases}from'../tools/pm2-maintenance-fixtures.mjs';
import{schemaBeforePM2Maintenance}from'./helpers/pm2-maintenance-schema.mjs';
const root=path.resolve(import.meta.dirname,'..');
test('exact independent PM2 stop ABI retains every actual original version and all signed fifty packages',()=>{
 const cases=pm2MaintenanceCases(root);assert(cases.filter(c=>c.name.startsWith('actual-original-PM2:')).length===11);
 for(const c of cases)assert.equal(validateManifest(c.manifest).length===0,c.valid,c.name);
});
test('new PM2 ABI schema reverses only its exact reviewed additions to the authentic predecessor',()=>{
 const current=JSON.parse(fs.readFileSync(path.join(root,'schema/app.schema.json')));
 const before=schemaBeforePM2Maintenance(current);assert.equal(sha256(canonical(before)),'1baa1e14325e5b2e236a14ecee42bdd09a7cb112c2df86ba77017c4e9c0f38d9');
 const changed=structuredClone(current);changed.properties.version.maxLength=79;assert.throws(()=>schemaBeforePM2Maintenance(changed));
 const missing=structuredClone(current);missing.allOf.pop();assert.throws(()=>schemaBeforePM2Maintenance(missing));
});

