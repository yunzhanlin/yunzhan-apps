import {schemaBeforeIntegrityKernel} from './helpers/integrity-kernel-schema.mjs';
import fs from 'node:fs';import test from 'node:test';import assert from 'node:assert/strict';import {fileURLToPath} from 'node:url';
import {analyticsNavigationCases} from '../tools/analytics-navigation-fixtures.mjs';
import {canonical,sha256,validateManifest} from '../tools/lib.mjs';
import {schemaBeforeAnalyticsNavigation} from './helpers/analytics-navigation-schema.mjs';
const root=fileURLToPath(new URL('../',import.meta.url));
for(const c of analyticsNavigationCases(root))test('navigation241 exact manifest '+c.name,()=>assert.equal(validateManifest(c.manifest).length===0,c.valid,c.name));
test('navigation schema preserves the complete original R3 schema without mutating the input',()=>{
 const s=JSON.parse(fs.readFileSync(root+'/schema/app.schema.json')),original=JSON.stringify(s);
 assert.equal(sha256(canonical(schemaBeforeAnalyticsNavigation(s))),'a333d5262d9a9af9e46cd5a1ac78e44f3d47aef058efb0d9992d423df7afc440');assert.equal(JSON.stringify(s),original);
});
for(const kind of['missing-feature','duplicate-feature','wrong-provider','missing-handler','missing-own-guard','missing-route-alternative','missing-future-alternative','weakened-old-guard','unrelated','duplicate-guard','duplicate-branch'])test('navigation historical projection rejects '+kind,()=>{
 const s=schemaBeforeIntegrityKernel(JSON.parse(fs.readFileSync(root+'/schema/app.schema.json'))),feature='analytics-navigation-order-v1',flags=s.properties.required_panel_features.items.enum;
 if(kind==='missing-feature')flags.pop();if(kind==='duplicate-feature')flags.push(feature);if(kind==='wrong-provider')s.allOf[0].then.oneOf.at(-1).properties.delivery.properties.provider.const='compose';if(kind==='missing-handler')s.allOf[0].then.oneOf.at(-1).properties.required_panel_features.items.enum.pop();
 if(kind==='missing-own-guard')s.allOf.pop();if(kind==='missing-route-alternative')s.allOf.at(-3).then.anyOf.pop();if(kind==='missing-future-alternative')s.allOf.at(-2).then.anyOf.pop();if(kind==='weakened-old-guard')s.allOf.at(-2).if.properties.version.pattern='.*';if(kind==='unrelated')s.title='unreviewed';if(kind==='duplicate-guard')s.allOf.push(structuredClone(s.allOf.at(-1)));if(kind==='duplicate-branch')s.allOf[0].then.oneOf.push(structuredClone(s.allOf[0].then.oneOf.at(-1)));
 assert.throws(()=>schemaBeforeAnalyticsNavigation(s));
});
