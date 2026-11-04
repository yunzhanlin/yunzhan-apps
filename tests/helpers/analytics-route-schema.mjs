import {schemaBeforeAnalyticsNavigation} from './analytics-navigation-schema.mjs';
// Reverse only C59's closed additive route scope for historical whole-schema
// pins. All older predicates and unrelated edits remain bound to their digest.
import assert from 'node:assert/strict';
import {canonical,sha256} from '../../tools/lib.mjs';
export function schemaBeforeAnalyticsRoute(value){
 const s=schemaBeforeAnalyticsNavigation(value),feature='analytics-route-readiness-v1',flags=s.properties.required_panel_features.items.enum;
 const branches=s.allOf[0].then.oneOf;
 if(!flags.includes(feature)&&!branches.some(v=>v.properties?.version?.const==='2.4.0'&&v.properties?.id?.const==='website-analytics'))return s;
 assert.equal(flags.filter(v=>v===feature).length,1);assert.equal(flags.at(-1),feature);flags.pop();
 assert.equal(sha256(canonical(branches.at(-1))),'ec9131d2149966d0f6503bce77472341a43a41157ce8732c2c3ddd356f373b89');branches.pop();
 assert.equal(sha256(canonical(s.allOf.at(-1))),'d37acdb02eab99abb2b98cb61063d8d0a273b1cef8da23f13b5e0044df9cf02f');s.allOf.pop();
 assert.equal(sha256(canonical(s.allOf.at(-1))),'16e7b60ce46416d8fbb9a53e3e5f5e681cef20362fb14f5c806add95e49e23a8');s.allOf.pop();
 assert.equal(sha256(canonical(s)),'08c8e8421afd0d8101eb0081b188f17e07be9a6735c28fc317ec32f56c8828d4','Every preRoute schema predicate and original C58 contract must remain exact');return s;
}
