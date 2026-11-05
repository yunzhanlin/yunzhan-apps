import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import {fileURLToPath}from 'node:url';
import {canonical,sha256}from '../tools/lib.mjs';
const root=fileURLToPath(new URL('../',import.meta.url)),feature='files-sync-root-independent-backup-v1';
const exact={required:['id','version','delivery','required_panel_features'],properties:{id:{const:'files-sync'},version:{const:'2.0.0'},delivery:{required:['provider','target','manage_route'],properties:{provider:{const:'panel-module'},target:{const:'files-sync'},manage_route:{const:'app-modules'}}},required_panel_features:{const:[feature]}}};
for(const name of ['schema/app.schema.json','candidate/schema/app.schema.json'])test('new independent-copy ABI preserves every previous schema constraint: '+name,()=>{
 const projected=JSON.parse(fs.readFileSync(root+name));
 const features=projected.properties.required_panel_features.items.enum;assert.equal(features.filter(v=>v===feature).length,1);features.splice(features.indexOf(feature),1);
 assert.deepEqual(projected.allOf.pop(),{if:{required:['required_panel_features'],properties:{required_panel_features:{contains:{const:feature}}}},then:exact});
 assert.deepEqual(projected.allOf.pop(),{if:{required:['id'],properties:{id:{const:'files-sync'}}},then:{anyOf:[{properties:{version:{pattern:'^[01](?:\\.(?:0|[1-9][0-9]*)){0,3}(?:-[A-Za-z0-9]+(?:[.-][A-Za-z0-9]+)*)?$'}}},exact]}});
 assert.deepEqual(projected.allOf[0].then.oneOf.pop(),exact);
 assert.equal(sha256(canonical(projected)),'9cee878222b789627dd0efbfd30b5b2a2222adcabaa6a0da2ff6fd81fb67db18','All old schema predicates must retain their original meaning; no replacement digest or broad exception');
});
