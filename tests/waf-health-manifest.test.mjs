import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import {validateManifest} from '../tools/lib.mjs';
const old=JSON.parse(fs.readFileSync(new URL('../dist/apps/nginx-waf/2.5.1/manifest.json',import.meta.url))),feature='waf-bound-health-v1';
const candidate=()=>({...structuredClone(old),version:'2.5.2',required_panel_features:[feature]});
test('site-bound health application cannot borrow an old, future, aliased or foreign panel handler',()=>{
 assert.deepEqual(validateManifest(old),[]);assert.deepEqual(validateManifest(candidate()),[]);
 const variants=[{version:'2.5.1'},{version:'2.5.2-preview'},{version:'2.5.3'},{version:'2.6.0'},{version:'18446744073709551616.0'},{id:'apache-waf'},{required_panel_features:[]},{required_panel_features:null},{required_panel_features:[feature,feature]},{required_panel_features:[feature,'intrusion-preserving-journal-v2']},{required_panel_features:['waf-bound-health-v2']},{delivery:{provider:'runtime',target:'nginx-waf',manage_route:'security'}},{delivery:{provider:'panel-module',target:'apache-waf',manage_route:'security'}},{delivery:{provider:'panel-module',target:'nginx-waf',manage_route:'app-modules'}}];
 for(const change of variants)assert(validateManifest({...candidate(),...change}).length,JSON.stringify(change));
 const missing=candidate();delete missing.required_panel_features;assert(validateManifest(missing).length);
 for(const version of ['2.5.3','2.6.0']){const m={...missing,version};assert(validateManifest(m).length)}
});
test('schema binds the mandatory single feature to the exact fixed WAF delivery',()=>{
 const s=JSON.parse(fs.readFileSync(new URL('../schema/app.schema.json',import.meta.url)));assert(s.properties.required_panel_features.items.enum.includes(feature));
 const p=s.allOf[0].then.oneOf.find(v=>v.properties.id.const==='nginx-waf').properties;assert.equal(p.version.const,'2.5.2');assert.equal(p.delivery.properties.target.const,'nginx-waf');assert.equal(p.delivery.properties.manage_route.const,'security');assert.equal(p.required_panel_features.maxItems,1);assert(s.allOf.some(v=>v.if?.properties?.id?.const==='nginx-waf'&&v.then.required.includes('required_panel_features')));
});
