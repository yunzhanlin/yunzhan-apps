import {schemaBeforeAnalyticsNavigation} from './helpers/analytics-navigation-schema.mjs';
import test from 'node:test';
import assert from 'node:assert/strict';
import {fileURLToPath} from 'node:url';
import {analyticsRouteCases} from '../tools/analytics-route-fixtures.mjs';
import {validateManifest} from '../tools/lib.mjs';
import fs from 'node:fs';
import {canonical,sha256} from '../tools/lib.mjs';
import {schemaBeforeAnalyticsRoute} from './helpers/analytics-route-schema.mjs';
const root=fileURLToPath(new URL('../',import.meta.url));
for(const c of analyticsRouteCases(root))test('route240 manifest ABI '+c.name,()=>assert.equal(validateManifest(c.manifest).length===0,c.valid,c.name));
test('route schema extension preserves every original C58 predicate and does not mutate the current schema',()=>{
 const schema=JSON.parse(fs.readFileSync(root+'/schema/app.schema.json')),before=JSON.stringify(schema);
 assert.equal(sha256(canonical(schemaBeforeAnalyticsRoute(schema))),'08c8e8421afd0d8101eb0081b188f17e07be9a6735c28fc317ec32f56c8828d4');assert.equal(JSON.stringify(schema),before);
});
for(const kind of['missing-feature','duplicate-feature','wrong-provider','missing-handler','missing-route-guard','missing-future-guard','weakened-future','unrelated','duplicate-guard'])test('route schema historical projection rejects '+kind,()=>{
 const s=schemaBeforeAnalyticsNavigation(JSON.parse(fs.readFileSync(root+'/schema/app.schema.json'))),feature='analytics-route-readiness-v1',flags=s.properties.required_panel_features.items.enum;
 if(kind==='missing-feature')flags.pop();if(kind==='duplicate-feature')flags.push(feature);if(kind==='wrong-provider')s.allOf[0].then.oneOf.at(-1).properties.delivery.properties.provider.const='compose';if(kind==='missing-handler')s.allOf[0].then.oneOf.at(-1).properties.required_panel_features.items.enum.pop();
 if(kind==='missing-route-guard')s.allOf.splice(-2,1);if(kind==='missing-future-guard')s.allOf.pop();if(kind==='weakened-future')s.allOf.at(-1).if.properties.version.pattern='.*';if(kind==='unrelated')s.title='unreviewed change';if(kind==='duplicate-guard')s.allOf.push(structuredClone(s.allOf.at(-1)));
 assert.throws(()=>schemaBeforeAnalyticsRoute(s));
});
