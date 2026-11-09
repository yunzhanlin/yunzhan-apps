import fs from 'node:fs';
import path from 'node:path';
import assert from 'node:assert/strict';
import test from 'node:test';
import {canonical,sha256,validateManifest} from '../tools/lib.mjs';
import {pm2RootVendorCases} from '../tools/pm2-root-vendor-fixtures.mjs';
import {schemaBeforePM2RootVendor} from './helpers/pm2-root-vendor-schema.mjs';
const root=path.resolve(import.meta.dirname,'..');

test('PM2 Root vendor release requires exact compiled compat11; original PM2 versions and all 50 signed package identities retain their contract',()=>{
 const cases=pm2RootVendorCases(root);
 assert.equal(cases.filter(c=>c.name.startsWith('actual-original-PM2:')).length,11);
 for(const c of cases)assert.equal(validateManifest(c.manifest).length===0,c.valid,c.name);
 const old=fs.readFileSync(path.join(root,'candidate/dist/apps/pm2-manager/7.0.4-compat10/manifest.json'));
 assert.equal(sha256(old),'d85fa662c22b2fd9a1e111995c320e39d8e51f4765bfd9ebc226c643b6d8d959');
});

test('new Root vendor schema preserves the complete prior publisher schema, and refuses damaged gate structure',()=>{
 const current=JSON.parse(fs.readFileSync(path.join(root,'schema/app.schema.json')));
 assert.equal(sha256(canonical(schemaBeforePM2RootVendor(current))),'02f341da39960324cc8830e02506387b762fce848323dd108b05ff2e50a0f6e7');
 const missing=structuredClone(current);missing.allOf.pop();assert.throws(()=>schemaBeforePM2RootVendor(missing));
 const changed=structuredClone(current);changed.allOf.at(-1).then.properties.version.const='7.0.4-compat12';assert.throws(()=>schemaBeforePM2RootVendor(changed));
 const duplicate=structuredClone(current);duplicate.properties.required_panel_features.items.enum.push('pm2-root-vendor-v1');assert.throws(()=>schemaBeforePM2RootVendor(duplicate));
});
