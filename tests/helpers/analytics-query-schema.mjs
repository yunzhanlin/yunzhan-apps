import assert from 'node:assert/strict';
import {schemaBeforeFilesSyncUnpublished}from './files-sync-unpublished-schema.mjs';
import {canonical,sha256} from '../../tools/lib.mjs';
const feature='website-analytics-query-context-v1';
export function schemaBeforeAnalyticsQuery(value){
 const s=schemaBeforeFilesSyncUnpublished(value),features=s.properties.required_panel_features.items.enum,branches=s.allOf[0].then.oneOf;
 if(!features.includes(feature)&&!branches.some(v=>v.properties?.version?.const==='2.4.2'&&v.properties?.id?.const==='website-analytics'))return s;
 assert.equal(features.filter(v=>v===feature).length,1);assert.equal(features.at(-1),feature);features.pop();
 assert.equal(sha256(canonical(branches.pop())),'f056154c262f3eaa5e0ab968d8c6c51e87621051bc9a484c9064d5773b0120cf');
 assert.equal(sha256(canonical(s.allOf.pop())),'ed8190fcb3bb1139c5c09f96506fd12ea82386dbd6a4d225c9bbccf84dff911d');
 for(const index of[25,26]){assert.equal(s.allOf[index].then.anyOf.length,3);assert.equal(sha256(canonical(s.allOf[index].then.anyOf.pop())),'f056154c262f3eaa5e0ab968d8c6c51e87621051bc9a484c9064d5773b0120cf');}
 assert.deepEqual(Object.keys(s.allOf[27].then),['anyOf']);assert.equal(s.allOf[27].then.anyOf.length,2);
 assert.equal(sha256(canonical(s.allOf[27].then.anyOf[1])),'f056154c262f3eaa5e0ab968d8c6c51e87621051bc9a484c9064d5773b0120cf');s.allOf[27].then=s.allOf[27].then.anyOf[0];
 assert.equal(sha256(canonical(s)),'8c349cf95515f7a1678b8e8a65928da9e732772c7b8d075759f0fb2a792c4c40','Every preQuery C62 schema predicate must remain exact');
 return s;
}
