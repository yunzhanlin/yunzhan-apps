// Remove only the reviewed Files Sync200 addition, then require the complete
// unchanged predecessor schema. Older projection helpers keep their digests.
import assert from 'node:assert/strict';
import {canonical,sha256} from '../../tools/lib.mjs';
const feature='files-sync-root-independent-backup-v1';
const exact={required:['id','version','delivery','required_panel_features'],properties:{id:{const:'files-sync'},version:{const:'2.0.0'},delivery:{required:['provider','target','manage_route'],properties:{provider:{const:'panel-module'},target:{const:'files-sync'},manage_route:{const:'app-modules'}}},required_panel_features:{const:[feature]}}};
export function schemaBeforeFilesSyncIndependent(value){
 const s=structuredClone(value),features=s.properties.required_panel_features.items.enum,branches=s.allOf[0].then.oneOf;
 if(!features.includes(feature)&&!branches.some(v=>v.properties?.id?.const==='files-sync'))return s;
 assert.equal(features.filter(v=>v===feature).length,1);assert.equal(features.at(-1),feature);features.pop();
 assert.deepEqual(s.allOf.pop(),{if:{required:['required_panel_features'],properties:{required_panel_features:{contains:{const:feature}}}},then:exact});
 assert.deepEqual(s.allOf.pop(),{if:{required:['id'],properties:{id:{const:'files-sync'}}},then:{anyOf:[{properties:{version:{pattern:'^[01](?:\\.(?:0|[1-9][0-9]*)){0,3}(?:-[A-Za-z0-9]+(?:[.-][A-Za-z0-9]+)*)?$'}}},exact]}});
 assert.deepEqual(branches.pop(),exact);
 assert.equal(sha256(canonical(s)),'9cee878222b789627dd0efbfd30b5b2a2222adcabaa6a0da2ff6fd81fb67db18','Every preKernel Files Sync predecessor schema predicate must remain exact');
 return s;
}
