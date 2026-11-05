import test from'node:test';
import assert from'node:assert/strict';
import fs from'node:fs';
import {schemaBeforeEnterpriseKernel,schemaBeforeIntegrityKernel}from'./helpers/integrity-kernel-schema.mjs';
import {canonical,sha256}from'../tools/lib.mjs';
const current=JSON.parse(fs.readFileSync(new URL('../schema/app.schema.json',import.meta.url)));
test('enterprise schema preserves the complete original C60 and pre-kernel predicates',()=>{
 assert.equal(sha256(canonical(schemaBeforeEnterpriseKernel(current))),'9fd25b306962ce8ce9c6d99583f24270184fccd3fbb7784e4ed7bd772cf403b6');
 assert.equal(sha256(canonical(schemaBeforeIntegrityKernel(current))),'fa7371e96f4983a668ff413c6c273ee9aabe0527559f70d9dd0633ec55e4d096');
});
for(const[name,change]of[
 ['missing feature',s=>s.properties.required_panel_features.items.enum.pop()],
 ['duplicate feature',s=>s.properties.required_panel_features.items.enum.push('enterprise-integrity-kernel-ownership-v1')],
 ['borrowed target',s=>s.allOf[0].then.oneOf.at(-1).properties.delivery.properties.target.const='website-tamper-proof'],
 ['changed guard',s=>s.allOf.at(-1).then.properties.version.const='1.5.1'],
 ['missing guard',s=>s.allOf.pop()],
 ['duplicated guard',s=>s.allOf.push(structuredClone(s.allOf.at(-1)))],
 ['old predicate changed',s=>s.properties.version.maxLength=1000],
])test('enterprise projection refuses '+name,()=>{const s=structuredClone(current);change(s);assert.throws(()=>schemaBeforeEnterpriseKernel(s));});
